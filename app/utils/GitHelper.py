#!/usr/bin/env python3

import git
import os
import subprocess

class GitHelper:
    @staticmethod
    def shallowClone(repoPath, repoUrl, commitHash, logger=None, depth=2):
        def log(message):
            if logger is not None:
                logger.info(message)
            else:
                print(message)

        # Workaround to allow GitPython within Docker environments due to file permissions
        subprocess.run(['git', 'config', '--global', '--replace-all', 'safe.directory', '*'])

        # If the repository already exists at the correct commit hash, then skip cloning
        if os.path.exists(repoPath):
            existingRepo = git.Repo(repoPath)
            if existingRepo.head.commit.hexsha.startswith(commitHash):
                log(f"Repository already exists at {repoPath} with the correct commit hash. Skipping clone.")
                return repoPath
            else:
                log(f"Repository already exists at {repoPath} but with a different commit hash. Removing and recloning.")
                subprocess.run(['rm', '-rf', repoPath])
        else:
            log(f"Cloning repository {repoUrl} at commit {commitHash} into {repoPath}.")
            repo = git.Repo.init(repoPath)
            origin = repo.create_remote('origin', repoUrl) if 'origin' not in repo.remotes else repo.remotes.origin
            # 2 depth needed to allow diffing from the parent
            origin.fetch(commitHash, depth=depth)
            repo.git.checkout('FETCH_HEAD')
            log(f"Successfully cloned repository at {repoPath} with commit {commitHash}.")

        return repoPath
    
    @staticmethod
    def diffFiles(repoPath, commitHash):
        repo = git.Repo(repoPath)
        commit = repo.commit(commitHash)

        if not commit.parents:
            # If we have no commit parents, then this is the initial commit
            emptyTreeHash = repo.git.hash_object("-t", "tree", "/dev/null")
            diff = repo.git.diff(emptyTreeHash, commitHash, name_only=True, diff_filter="d")
        else:
            diff = repo.git.diff(f"{commitHash}~1", commitHash, name_only=True, diff_filter="d")

        changedFiles = diff.splitlines()
        return changedFiles
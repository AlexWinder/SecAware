#!/usr/bin/env python3

import git
import os
import subprocess

class GitHelper:
    @staticmethod
    def shallowClone(repoPath, repoUrl, commitHash):
        # Workaround to allow GitPython within Docker environments due to file permissions
        subprocess.run(['git', 'config', '--global', '--replace-all', 'safe.directory', '*'])

        # If the repository already exists at the correct commit hash, then skip cloning
        if os.path.exists(repoPath):
            existingRepo = git.Repo(repoPath)
            if existingRepo.head.commit.hexsha.startswith(commitHash):
                print(f"Repository already exists at {repoPath} with the correct commit hash. Skipping clone.")
                return repoPath
            else:
                print(f"Repository already exists at {repoPath} but with a different commit hash. Removing and recloning.")
                subprocess.run(['rm', '-rf', repoPath])
        else:
            print(f"Cloning repository {repoUrl} at commit {commitHash} into {repoPath}...")
            repo = git.Repo.init(repoPath)
            origin = repo.create_remote('origin', repoUrl) if 'origin' not in repo.remotes else repo.remotes.origin
            # 2 depth needed to allow diffing from the parent
            origin.fetch(commitHash, depth=2)
            repo.git.checkout('FETCH_HEAD')

        return repoPath
    
    @staticmethod
    def diffFiles(repoPath, commitHash):
        repo = git.Repo(repoPath)
        diff = repo.git.diff(f"{commitHash}~1", commitHash, name_only=True)
        changedFiles = diff.splitlines()
        return changedFiles
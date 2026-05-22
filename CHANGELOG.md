# CHANGELOG

## 0.2.0 - 2026-05-22

- Feature: Added SecAware version into the report.
- Feature: Added support for `--scan-identifier` which, when populated, will be included in the final report to act as an identifier of a scan. This is also used within the report directory path to avoid commit reference conflicts.
- Feature: Added standard deviation to output report of SCA component for CVEs and weak links.
- Feature: Added AI token usage into reports.
- Feature: Added missing minimum dependency version age from SCA report.
- Feature: Added `60` second timeout when calling the generative AI API.
- Feature: Repeat failed calls for all requests to the AI API, rather than just vulnerability scanning.
- Fix: Improved documentation to make clear that SecAware is currently focused only on PHP applications.
- Fix: Git clone hangs on credential prompt if the repository no longer exists.
- Fix: SCA crashes during report generation if no CVEs or weak links found.
- Fix: Handle crashes from Psalm causing the whole process to fail.
- Fix: Deleted files are included in the vulnerability scan, causing crashes due to file not found.
- Fix: SCA fails for dependencies that cannot be found via the Packagist API.
- Fix: Project is not cloned if there is no parent commit beyond the provided git reference.
- Fix: SecAware report not generated if SCA is not executed (such as missing `composer.json`).
- Fix: Improved error handling from AI API provider.
- Fix: Improved wording of statistical measurements in SCA component report.
- Fix: `Dockerfile` updated from Python `3.14.3` to `3.14.4`.
- Fix: Removed hard-set of PHP `8.4.18` due to missing dependency. Instead install to latest `8.4`.

## 0.1.1 - 2026-03-31

- Feature: Added architecture and state diagrams to `README`.
- Fix: Improved documentation for Hugging Face in the `README`.
- Fix: Improve handling within contextualised report where no vulnerabilities are found.
- Fix: Improve handling of failures within the upstream generative AI API.
- Fix: Adjusted to use PHP `8.4` rather than `8.5` due to errors within Psalm.

## 0.1.0 - 2026-03-20

- Initial release.

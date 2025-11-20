# Changelog

## [2.0.3](https://github.com/crowdstrike/fcs-action/compare/v2.0.2...v2.0.3) (2025-11-20)


### Bug Fixes

* enable GitHub severity levels for SARIF files ([#49](https://github.com/crowdstrike/fcs-action/issues/49)) ([a17e7b3](https://github.com/crowdstrike/fcs-action/commit/a17e7b39c96fec3f0892a5141a26fe2e24aeb4ed))
* handle output path filenames for IaC SARIF conversion and null fields in image scans ([#50](https://github.com/crowdstrike/fcs-action/issues/50)) ([e6b3a9c](https://github.com/crowdstrike/fcs-action/commit/e6b3a9c6b81820163d1566c48b5429b00c35ca69))


### Miscellaneous

* release-please manifest files ([f85683c](https://github.com/crowdstrike/fcs-action/commit/f85683cee79a91355bfe96db22fbd36c068c0a3f))
* update gitignore ([093d734](https://github.com/crowdstrike/fcs-action/commit/093d734ff4b2f97dab6a59b8654448065227ab11))

## [2.0.2](https://github.com/CrowdStrike/fcs-action/compare/v2.0.1...v2.0.2) (2025-09-12)


### Bug Fixes

* adds timeout support for image scan, cleans up docs, and ensure output path dir exists for iac ([#41](https://github.com/CrowdStrike/fcs-action/issues/41)) ([3f8c435](https://github.com/CrowdStrike/fcs-action/commit/3f8c435b6f8ccb6064e6f29ff54a877aca14ccaa))

## [2.0.1](https://github.com/CrowdStrike/fcs-action/compare/v2.0.0...v2.0.1) (2025-09-10)


### Miscellaneous

* minor updates ([22bda06](https://github.com/CrowdStrike/fcs-action/commit/22bda06ea32681c6896a9ad30ec776193411feac))

## [2.0.0](https://github.com/CrowdStrike/fcs-action/compare/v1.1.0...v2.0.0) (2025-08-15)


### ⚠ BREAKING CHANGES

* Latest FCS CLI with Image Assessment ([#29](https://github.com/CrowdStrike/fcs-action/issues/29))

### Features

* Latest FCS CLI with Image Assessment ([#29](https://github.com/CrowdStrike/fcs-action/issues/29)) ([82645d0](https://github.com/CrowdStrike/fcs-action/commit/82645d07dbb863638742b5991c2a47570bc810a8))


### Bug Fixes

* updated sarif to fix iac and uri concerns ([#31](https://github.com/CrowdStrike/fcs-action/issues/31)) ([6111f24](https://github.com/CrowdStrike/fcs-action/commit/6111f24173e6b06347c7551a6394665eade88dd5))

## [1.1.0](https://github.com/CrowdStrike/fcs-action/compare/v1.0.6...v1.1.0) (2025-05-16)


### Features

* add new policy_rule option and doc changes for newer cli version ([#26](https://github.com/CrowdStrike/fcs-action/issues/26)) ([64cf4ad](https://github.com/CrowdStrike/fcs-action/commit/64cf4ad954614cf7b674ef51ac9dcdc215c4aea9))

## [1.0.6](https://github.com/crowdstrike/fcs-action/compare/v1.0.5...v1.0.6) (2024-10-19)


### Bug Fixes

* use bin from container to fix permission issues ([#21](https://github.com/crowdstrike/fcs-action/issues/21)) ([af3c6c1](https://github.com/crowdstrike/fcs-action/commit/af3c6c1521fe352c1289cdced46211d9be5eee89))

## [1.0.5](https://github.com/crowdstrike/fcs-action/compare/v1.0.4...v1.0.5) (2024-08-26)


### Miscellaneous

* release 1.0.5 ([#17](https://github.com/crowdstrike/fcs-action/issues/17)) ([62fdc91](https://github.com/crowdstrike/fcs-action/commit/62fdc91bfb6a3291b338ffbe7a7aba4ca6793002))

## [1.0.4](https://github.com/crowdstrike/fcs-action/compare/v1.0.3...v1.0.4) (2024-08-26)

## [1.0.3](https://github.com/crowdstrike/fcs-action/compare/v1.0.2...v1.0.3) (2024-08-26)


### Miscellaneous

* add branding for actions.yml ([#14](https://github.com/crowdstrike/fcs-action/issues/14)) ([ec5cf44](https://github.com/crowdstrike/fcs-action/commit/ec5cf444a9e495d9b3637b93272bbeb424685574))
* release 1.0.3 ([223d540](https://github.com/crowdstrike/fcs-action/commit/223d540d93b96cba622c4fbb3d55743f7b1d4ead))

## [1.0.2](https://github.com/CrowdStrike/fcs-action/compare/v1.0.1...v1.0.2) (2024-08-13)


### Bug Fixes

* fixing sarif informationuri issue temporarily ([#9](https://github.com/CrowdStrike/fcs-action/issues/9)) ([75e518f](https://github.com/CrowdStrike/fcs-action/commit/75e518ff7374d8eab95908b0a3811ac28806d049))

## [1.0.1](https://github.com/crowdstrike/fcs-action/compare/v1.0.0...v1.0.1) (2024-07-12)


### Bug Fixes

* allow path and config to coexist ([#7](https://github.com/crowdstrike/fcs-action/issues/7)) ([3147eaf](https://github.com/crowdstrike/fcs-action/commit/3147eaf8c8953f4521d677d9fddcabcbdfa42b02))

## 1.0.0 (2024-07-12)


### Features

* initial commit containing first crack ([539230d](https://github.com/CrowdStrike/fcs-action/commit/539230d91b06ce1776d225d7b6e8dc50cc9b64f5))


### Bug Fixes

* refactor and enhance existing content ([#3](https://github.com/CrowdStrike/fcs-action/issues/3)) ([e53ca70](https://github.com/CrowdStrike/fcs-action/commit/e53ca7084358ffdb4f5e2e676b0aa82dcc364cf7))

[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_peepdf-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-peepdf)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-peepdf)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-peepdf)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-peepdf)](./LICENSE)
# PeePDF Service

This Assemblyline service uses the Python PeePDF library against PDF files.

## Service Details

### PDF File Information

- MD5
- SHA1
- SHA256
- Size
- Version
- Binary (T|F)
- Linearized  (T|F)
- Encryption Algorithms
- Updates
- Objects
- Streams
- Versions Info:
    - Catalog
    - Info
    - Objects
    - Streams
    - Xref streams
    - Compressed Objects
    - Encoded
    - Objects with JS code

### Other Items of Interest

- CVE identifiers
- Embedded files (will attempt to extract)
- Javascript (will attempt to extract)
- URL detection

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name PeePDF \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-peepdf

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service PeePDF

Ce service Assemblyline utilise la bibliothèque Python PeePDF pour les fichiers PDF.

## Détails du service

### Informations sur le fichier PDF

- MD5
- SHA1
- SHA256
- Taille du fichier
- Version
- Binaire (T|F)
- Linéarisée (T|F)
- Algorithmes de cryptage
- Mises à jour
- Objets
- Flux
- Versions Info :
    - Catalogue
    - Info : Catalogue
    - Objets
    - Flux
    - Flux Xref
    - Objets compressés
    - Encodés
    - Objets avec code JS

### Autres éléments d'intérêt

- Identifiants CVE
- Fichiers intégrés (tentative d'extraction)
- Javascript (tentative d'extraction)
- Détection d'URL

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Il s'agit d'un service d'Assemblyline. Il est optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name PeePDF \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-peepdf

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/

# AlfyChat — Service Serveurs

Microservice de gestion des serveurs communautaires pour AlfyChat.

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)
![License](https://img.shields.io/badge/License-Source_Available-blue)

## Rôle

Ce service gère la création, la configuration et l'administration des serveurs communautaires AlfyChat : canaux, membres, rôles, invitations et permissions. Inspiré d'une architecture P2P à la manière de TeamSpeak.

## Stack technique

| Catégorie | Technologies |
|-----------|-------------|
| Langage | Go 1.26 |
| API | net/http (stdlib) |
| Auth | JWT |
| Cache | Redis |
| Base de données | MySQL 8 |

## Architecture globale

```
Frontend (:4000)  →  Gateway (:3000)  →  Microservices
                                          ├── users    (:3001)
                                          ├── messages  (:3002)
                                          ├── friends   (:3003)
                                          ├── calls     (:3004)
                                          ├── servers   (:3005)  ← ce service
                                          ├── bots      (:3006)
                                          └── media     (:3007)
```

## Démarrage

### Prérequis

- [Go](https://go.dev/) ≥ 1.26
- MySQL 8
- Redis 7

### Variables d'environnement

```env
PORT=3005
DB_HOST=localhost
DB_PORT=3306
DB_USER=alfychat
DB_PASSWORD=
DB_NAME=alfychat_servers
REDIS_URL=redis://localhost:6379
JWT_SECRET=
SERVICE_REGISTRY_URL=http://gateway:3000
```

### Développement

```bash
go run .
```

### Build production

```bash
go build -o bin/service .
./bin/service
```

### Tests

```bash
go test ./...
```

### Docker

```bash
docker compose up servers
```

## Structure du projet

```
main.go                  # Point d'entrée
internal/
  platform/                # Socle commun (routeur, validation, auth, MySQL, Redis)
  servers/                 # Routes, permissions (bitmask), schéma, fichiers (images en MySQL), nettoyages
```

## Contribution

Voir [CONTRIBUTING.md](./CONTRIBUTING.md).

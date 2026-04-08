# AlfyChat — Service Serveurs

Microservice de gestion des serveurs communautaires pour AlfyChat.

![Node.js](https://img.shields.io/badge/Bun-1.2-black?logo=bun)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript)
![License](https://img.shields.io/badge/License-Source_Available-blue)

## Rôle

Ce service gère la création, la configuration et l'administration des serveurs communautaires AlfyChat : canaux, membres, rôles, invitations et permissions. Inspiré d'une architecture P2P à la manière de TeamSpeak.

## Stack technique

| Catégorie | Technologies |
|-----------|-------------|
| Runtime | Bun |
| Langage | TypeScript |
| API | Express |
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

- [Bun](https://bun.sh/) ≥ 1.2
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

### Installation

```bash
bun install
```

### Développement

```bash
bun run dev
```

### Build production

```bash
bun run build
bun run start
```

### Docker

```bash
docker compose up servers
```

## Structure du projet

```
src/
├── database.ts          # Connexion MySQL
├── redis.ts             # Connexion Redis
├── index.ts             # Point d'entrée
├── controllers/         # Logique métier (serveurs, canaux, membres, rôles)
├── routes/              # Définition des routes Express
├── services/            # Services métier
├── middleware/          # Auth JWT, rate limiting
├── types/               # Types TypeScript
└── utils/               # Utilitaires
uploads/                 # Icônes et bannières serveur
```

## Contribution

Voir [CONTRIBUTING.md](./CONTRIBUTING.md).

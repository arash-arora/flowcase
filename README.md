# <div align="center">🌊 **Flowcase**</div>

<div align="center">

![Flowcase](https://img.shields.io/badge/Status-Development-yellow)
![License](https://img.shields.io/badge/license-MIT-blue)
![Docker](https://img.shields.io/badge/Docker-Required-blue)

**A cutting-edge open-source container streaming platform**

</div>

> [!CAUTION]
> This project is still in development and is not yet ready for production use. We do not currently support upgrading from older versions. Please use with caution.

## What is Flowcase?

**Flowcase** is a free and completely open-source alternative to Kasm Workspaces, enabling secure container streaming for your applications.

## Features

<div align="center">

| Open-Source | Secure Streaming | User-Friendly | Customizable | Multi-Platform |
|:-------------:|:------------------:|:----------------:|:--------------:|:--------------:|
| Completely free and community-driven | Stream applications securely using Docker | Easy to deploy and manage | Supports customization for various use cases | Supports Windows, Linux, and macOS |

</div>

## Prerequisites

Before getting started, ensure you have:

- Docker and Docker Compose installed on your machine
- A user with sudo/root access or a user in the `docker` group
- Basic knowledge of container management

## Setup Instructions

### 1. Download the `docker-compose.yml` file and place it in a folder of your choice.

```shell
curl -L https://raw.githubusercontent.com/flowcase/flowcase/refs/heads/main/docker-compose.yml -o docker-compose.yml
```

### 2. Launch with Docker Compose

```shell
docker compose up
```

> [!NOTE]
> Default admin and user logins will be displayed in the terminal output on initial startup.

### 3. Access Flowcase

Open your browser and navigate to:

```
http://localhost:80
```

## Session Timeout

Droplet sessions are automatically cleaned up if they remain inactive for a period
of time. Inactivity is tracked both when the user loads the droplet page _and_
via periodic heartbeats sent by the client while a session is open. This prevents
stale containers from lingering if a user forgets to destroy a droplet.

- Default timeout: **30 minutes**
- Heartbeats are sent every minute while the session is active
- You can override the timeout using the `SESSION_TIMEOUT_MINUTES` config value
  (via environment variable or `app.config`)


## Session Timeout

To prevent idle resource consumption, Flowcase will automatically terminate a
droplet session if it has been inactive for a configurable period. By default,
the timeout is **30 minutes**. Cleanup runs periodically in the background and
ais also triggered whenever users list or request new instances.

You can override the timeout by setting the `SESSION_TIMEOUT_MINUTES`
configuration variable (via environment or `app.config`).

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## Security
Please refer to [SECURITY.md](SECURITY.md) for more information.

---
<div align="center">
Made with ❤️ by the Flowcase Team
</div>

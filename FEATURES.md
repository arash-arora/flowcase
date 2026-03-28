# Flowcase Features Documentation

## Overview
Flowcase is a cutting-edge, open-source container streaming platform that serves as a free alternative to Kasm Workspaces. It enables secure streaming of containerized applications through a web interface, supporting Docker-based deployments with user authentication, role-based access control, and comprehensive management features.

## Core Features

### 1. Container Streaming
- **Secure Application Streaming**: Stream containerized applications securely over the web using Docker containers
- **Real-time Access**: Provides low-latency streaming of desktop environments and applications
- **Multi-Platform Support**: Supports Windows, Linux, and macOS containers
- **Resource Management**: Configurable CPU cores and memory limits per container instance

### 2. User Authentication & Authorization
- **Local Authentication**: Username/password-based login with bcrypt password hashing
- **OIDC Integration**: Support for OpenID Connect authentication providers
- **Role-Based Access Control**: Group-based permissions system with granular controls
- **Session Management**: Automatic session timeout (default 30 minutes) with heartbeat monitoring
- **Persistent Sessions**: Remember me functionality for extended sessions

### 3. Droplet Management
- **Droplet Types**: Support for different droplet types (container-based and potentially VM-based)
- **Container Configuration**: 
  - Docker image specification
  - Private registry authentication
  - Resource allocation (CPU cores, memory)
  - Persistent profile paths for user data
- **Instance Lifecycle**: Create, monitor, and destroy droplet instances
- **Access Control**: Group-based restrictions on droplet availability

## Administrative Guide

### Accessing the Admin Panel
To access administrative features, users must have the `perm_admin_panel` permission. Once logged in, click the "Admin" button in the navigation bar to open the admin panel.

### Managing Users

#### Creating a New User
1. Navigate to the Admin Panel → Users tab
2. Click the "Add User" button
3. Fill in the required fields:
   - **Username**: Unique identifier (no spaces allowed)
   - **Password**: Secure password for authentication
   - **Groups**: Select one or more groups to assign permissions
4. Click "Save" to create the user

#### Editing an Existing User
1. In the Users tab, click on an existing user
2. Modify the username or group assignments as needed
3. Note: Passwords cannot be changed through the admin interface for security reasons

#### Deleting a User
1. Select the user from the list
2. Click the "Delete" button
3. Confirm the deletion (this action cannot be undone)

### Managing Groups

#### Creating a New Group
1. Navigate to Admin Panel → Groups tab
2. Click "Add Group"
3. Enter a **Display Name** for the group
4. Configure permissions by checking the appropriate boxes:
   - **Admin Panel**: Access to administrative functions
   - **View/Edit Instances**: Monitor and manage running droplet instances
   - **View/Edit Users**: User account management
   - **View/Edit Droplets**: Droplet configuration management
   - **View/Edit Registry**: Docker registry management
   - **View/Edit Groups**: Group and permission management
5. Optionally assign droplets that this group can access
6. Click "Save"

#### Editing Groups
1. Select a group from the list
2. Modify permissions or assigned droplets
3. Note: Protected groups cannot be deleted

### Managing Droplets

#### Creating a Container Droplet
1. Go to Admin Panel → Droplets tab
2. Click "Add Droplet"
3. Configure the following:
   - **Display Name**: User-friendly name
   - **Description**: Optional description
   - **Droplet Type**: Select "container"
   - **Docker Image**: Full image name (e.g., `ubuntu:20.04`)
   - **Docker Registry**: Optional private registry URL
   - **Registry Username/Password**: Credentials for private registries
   - **Cores**: CPU cores to allocate (decimal values allowed)
   - **Memory**: RAM in MB
   - **Persistent Profile Path**: Directory for user data (e.g., `/home/user`)
   - **Network**: Select Docker network for isolation
   - **Allowed Groups**: Groups that can access this droplet
4. Click "Save"

#### Creating Server-Based Droplets (VNC/RDP/SSH)
1. Follow steps 1-2 above
2. Select droplet type: "vnc", "rdp", or "ssh"
3. Provide server connection details:
   - **Server IP**: IP address of the target server
   - **Server Port**: Connection port
   - **Server Username/Password**: Credentials for access
4. Configure allowed groups
5. Click "Save"

#### Enabling Persistent Paths
To enable persistent storage for user data:
1. When creating/editing a droplet, set **Persistent Profile Path** to a directory inside the container (e.g., `/home/user`)
2. Flowcase will mount user-specific directories to preserve files between sessions
3. Users can upload/download files through the droplet interface

#### Attaching Networks to Droplets
1. Create or sync Docker networks first (see Network Management)
2. When creating/editing a droplet, select the desired network from the **Network** dropdown
3. This provides network isolation between different droplet instances

#### Running a Droplet
Users with appropriate permissions can:
1. Log into the dashboard
2. Click on an available droplet
3. The system will create a new instance and redirect to the streaming interface
4. Use the control panel for fullscreen, file transfer, etc.

### Managing Docker Images

#### Installing a New Image
1. Go to Admin Panel → Images tab
2. View current image status
3. To pull a specific image:
   - Click "Pull Image" for a droplet
   - Or use "Pull All" to download images for all droplets
4. Monitor progress in the status view
5. Images are automatically pulled when users launch droplets if not already available

#### Using Private Registries
1. Configure registry credentials when creating the droplet
2. Or add registries globally in Admin Panel → Registry tab
3. Images from private registries will use the provided authentication

### Managing Networks

#### Syncing Docker Networks
1. Navigate to Admin Panel → Networks tab
2. Click "Sync Networks" to import existing Docker networks into Flowcase
3. This makes them available for droplet assignment

#### Creating Custom Networks
Docker networks must be created externally using Docker CLI or Docker Compose, then synced in Flowcase.

### Managing Registries

#### Adding a Registry
1. Go to Admin Panel → Registry tab
2. Click "Add Registry"
3. Enter the registry URL (e.g., `https://registry.example.com`)
4. Click "Save"

#### Using Registry Droplets
Registries can host droplet definitions that can be imported into Flowcase for easy deployment.

### Monitoring and Logs

#### Viewing System Information
- Admin Panel → System Info shows resource usage and system details

#### Viewing Logs
- Admin Panel → Logs tab displays application logs with filtering by level (DEBUG, INFO, WARNING, ERROR)

#### Managing Instances
- Admin Panel → Instances tab shows all running droplet instances
- Force destroy instances if needed
- Monitor resource usage and user activity

### Best Practices

#### Security
- Use strong passwords for all user accounts
- Assign minimal required permissions to groups
- Regularly review and audit user access
- Use private registries for sensitive images

#### Performance
- Monitor resource usage and adjust CPU/memory allocations
- Enable persistent paths only when needed
- Regularly clean up unused images and instances

#### Network Isolation
- Use separate Docker networks for different security zones
- Assign appropriate networks to droplets based on requirements

### 4. User Interface
- **Dashboard**: Clean, responsive web interface for accessing available droplets
- **Control Panel**: In-session controls including:
  - Fullscreen mode
  - Audio toggle
  - File upload/download
  - Display settings
  - Game mode optimization
  - Instance destruction
- **Admin Panel**: Comprehensive administrative interface for system management

### 5. File Management
- **Persistent Profiles**: User-specific persistent storage for documents, downloads, and custom configurations
- **File Upload**: Drag-and-drop file upload to running instances using Dropzone.js
- **File Download**: Download files from container instances
- **Profile Structure**: Organized directory structure (Desktop, Documents, Downloads, etc.)

### 6. Administrative Features
- **User Management**: Create, edit, and delete user accounts
- **Group Management**: Define permission groups with specific access rights
- **Droplet Administration**: Full CRUD operations on droplet definitions
- **Instance Monitoring**: View and manage active container instances
- **Network Management**: Configure Docker networks for container isolation
- **Registry Management**: Add and manage private Docker registries
- **System Monitoring**: View system information and resource usage
- **Logging System**: Comprehensive logging with DEBUG, INFO, WARNING, ERROR levels
- **Image Management**: Pull and manage Docker images with status tracking

### 7. Infrastructure & Deployment
- **Docker Integration**: Native Docker API integration for container management
- **Database Support**: PostgreSQL primary support with SQLite fallback
- **Scalable Architecture**: Designed for deployment in containerized environments
- **Nginx Integration**: Reverse proxy configuration for production deployments
- **Gunicorn WSGI**: Production-ready WSGI server configuration
- **Docker Compose**: Complete deployment orchestration

### 8. Security Features
- **Encrypted Passwords**: Secure password storage using bcrypt
- **Session Security**: Secure session handling with Flask-Login
- **Network Isolation**: Docker network segmentation
- **Access Logging**: Comprehensive audit logging
- **Permission Checks**: Fine-grained permission validation
- **Secret Key Management**: Automatic generation and secure storage

### 9. Monitoring & Maintenance
- **Heartbeat Monitoring**: Active session monitoring to detect inactive instances
- **Automatic Cleanup**: Background cleanup of stale container instances
- **Resource Monitoring**: System resource usage tracking
- **Log Aggregation**: Centralized logging for troubleshooting
- **Health Checks**: Instance health monitoring and status reporting

### 10. Extensibility
- **Plugin Architecture**: Modular design with blueprints for different features
- **API Endpoints**: RESTful API for programmatic access
- **Customizable UI**: CSS-based theming and customization
- **Configuration Flexibility**: Environment variable-based configuration
- **Migration Support**: Database migration tools for schema updates

## Technical Specifications

### Supported Platforms
- **Host Systems**: Linux, Windows, macOS
- **Container Platforms**: Docker
- **Databases**: PostgreSQL, SQLite
- **Web Browsers**: Modern browsers with WebSocket support

### Dependencies
- Flask 3.0.3 (Web framework)
- Docker Python SDK 7.1.0 (Container management)
- SQLAlchemy 3.1.1 (Database ORM)
- Flask-Login 0.6.3 (Authentication)
- APScheduler 3.10.4 (Background tasks)
- Authlib 1.2.1 (OIDC support)

### Default Configurations
- **Session Timeout**: 30 minutes
- **Heartbeat Interval**: 1 minute
- **Database**: PostgreSQL (with SQLite fallback)
- **Port**: 5000 (development), 80 (production)

## Use Cases
- **Remote Desktop Access**: Secure remote access to desktop environments
- **Application Streaming**: Stream specific applications without full desktop
- **Development Environments**: Isolated development containers
- **Educational Platforms**: Controlled access to software tools
- **Testing Environments**: Disposable test instances
- **Demo Systems**: Showcase applications in controlled environments

This documentation covers the key features of Flowcase as of the current development state. The platform is actively developed and new features may be added over time.</content>
<parameter name="filePath">/home/ubuntu/flowcase/FEATURES.md
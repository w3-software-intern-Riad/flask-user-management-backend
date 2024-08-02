# User Management API

This project is a User Management API built with Flask, Flask-RESTPlus, and PostgreSQL. It supports user registration, login, updating user information, resetting passwords, and deleting accounts. Additionally, it includes admin functionalities for promoting users and deleting user accounts.

## Features

- User registration
- User Login with JWT token creation
- CRUD operations for user information
- Password reset functionality
- Admin functionalities for user management
- Swagger UI documentation

## Getting Started

### Prerequisites

- Python 3.7 or later
- PostgreSQL
- Virtual environment (optional but recommended)

### Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/w3-software-intern-Riad/flask-user-management-backend.git
    cd your-repo-name
    ```

2. Create a virtual environment:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

4. Configure your PostgreSQL database and update the `SQLALCHEMY_DATABASE_URI` in `app.py`:
    ```python
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@localhost:5432/database_name'
    ```

5. Initialize the database:
    ```sh
    flask db init
    flask db migrate
    flask db upgrade
    ```

### Running the Application

1. Start the Flask application:
    ```sh
    flask run
    ```
   The application will run on `http://127.0.0.1:5000`.

### API Documentation

The API documentation is available at `http://127.0.0.1:5000/api/swagger`.

### API Endpoints

#### Auth Endpoints

- **Register**: `POST /register`
  - **Description**: Registers a new user. The request body must include the following fields:
    - `username`: The user's chosen username.
    - `firstname`: The user's first name.
    - `lastname`: The user's last name.
    - `password`: The user's password (will be hashed).
    - `email`: The user's email address.
    - `role` : By default USER
  - **Response**: A success message indicating that the user was created successfully or an error message if the registration fails.
- **Login**: `POST /login`
  - **Description**: Authenticates a user and provides a JWT token. The request body must include:
    - `email`: The user's email address.
    - `password`: The user's password.
  - **Response**: A JWT token is returned if the credentials are valid. This token must be included in the `Authorization` header for protected endpoints.


#### User Endpoints

- **Update User**: `PUT /user`
  - **Description**: Updates user information. Requires a valid JWT token for authentication. The request body can include any of the following fields:
    - `username`: The user's new username.
    - `firstname`: The user's new first name.
    - `lastname`: The user's new last name.
    - `password`: The user's new password (will be hashed).
    - `email`: The user's new email address.
    - `active`: The user's new active status (`true` or `false`).
  - **Response**: A success message if the user data is updated successfully or an error message if the update fails
- **Reset Password**: `PATCH /reset_password`
  - **Description**: Resets the user's password. Requires a valid JWT token for authentication. The request body must include:
    - `new_password`: The new password (will be hashed).
  - **Response**: A success message if the password is updated successfully or an error message if the reset fails.
- **Delete Account**: `DELETE /account`
  - **Description**: Deletes the user's account. Requires a valid JWT token for authentication.
  - **Response**: A success message if the account is deleted successfully or an error message if the deletion fails.

#### Admin Endpoints

**Admin Register**: `POST /admin/register`
- **Description**: Registers a new user as an admin. This route is used for the initial setup of the root admin account only. After successful registration, a file will be created indicating whether the root admin has been set up. If this file shows `root_admin_created: true`, further requests to this route will be blocked.
- **Request Body**:
  - `username`: The user's chosen username.
  - `firstname`: The user's first name.
  - `lastname`: The user's last name.
  - `password`: The user's password (will be hashed).
  - `email`: The user's email address.
  - `role`: By default, `ADMIN`.
- **Response**: 
  - **Success**: A message confirming the admin account was created successfully.
  - **Error**: An error message if registration fails or if the route has been accessed after the root admin setup is complete.

- **Update Admin Data**: `PUT /admin/update_profile`
  - **Description**: Updates admin information. Requires a valid JWT token for authentication. The request body can include any of the following fields:
    - `username`: The user's new username.
    - `firstname`: The user's new first name.
    - `lastname`: The user's new last name.
    - `password`: The user's new password (will be hashed).
    - `email`: The user's new email address.
    - `role` : The user's now set the role (ADMIN/USER)
    - `active`: The user's new active status (`true` or `false`).
  - **Response**: A success message if the user data is updated successfully or an error message if the update fails



- **Promote User**: `PUT /admin/promote/<int:user_id>`

  - **Description**: Promotes a user to an admin role. Requires a valid JWT token for authentication with an `ADMIN` role. The request body can include:
    - `role`: The new role for the user (`admin` or `user`).
    - can have other fields to change the other data of user's
  - **Response**: A success message if the user data updated successfully or an error message updation fails.
- **Delete User**: `DELETE /admin/delete_user/<int:user_id>`
  - **Description**: Deletes a user account. Requires a valid JWT token for authentication with an `ADMIN` role. The user being deleted must not be an admin.
  - **Response**: A success message if the user is deleted successfully or an error message if the deletion fails.

## Database Schema

The database schema for this application is managed using SQLAlchemy. The main model used in the application is the `User` model, which is described below:

### User Model

- **id**: `Integer` (Primary Key)
  - Unique identifier for each user.

- **username**: `String(80)`
  - The user's username (required).

- **firstname**: `String(80)`
  - The user's first name (required).

- **lastname**: `String(80)`
  - The user's last name (required).

- **password**: `String(255)`
  - The hashed password for authentication (required).

- **email**: `String(120)` (Unique)
  - The user's email address (required, unique).

- **role**: `Enum(RoleEnum)`
  - The user's role, which can be either `admin` or `user` (default is `user`).

- **created_at**: `DateTime`
  - Timestamp when the user was created (default is current timestamp).

- **updated_at**: `DateTime`
  - Timestamp when the user was last updated (default is `None`, updated automatically).

- **active**: `Boolean`
  - Indicates if the user account is active (default is `True`).

### Role Enum

The `RoleEnum` defines the possible roles for a user:
- **ADMIN**: Administrative user with additional privileges.
- **USER**: Regular user with standard privileges.


## JWT Authentication

This application uses JWT for authentication. Include the JWT token in the `Authorization` header for endpoints that require authentication:
`Authorization:` Bearer `<your-token>` (must use Bearer when add authorization in Swagger)

### Important Note for Swagger

**When using Swagger to test the API endpoints that require authentication, you must include the JWT token in the `Authorization` header in the following format:**
``` Bearer <your-token>```

**Ensure that you replace `<your-token>` with the actual JWT token received from the login endpoint. This format is crucial for proper authentication and to gain access to the protected endpoints, always keep the keyword ```Bearer``` also**


## Error Handling

The application provides proper error messages for common issues such as missing required fields, invalid credentials, unauthorized access, and more.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss your ideas.


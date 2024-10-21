# Project Documentation: Node.js API with Prisma and PostgreSQL

=============================================================

Table of Contents
-----------------

1. [Overview](#overview)
2. [Technologies](#technologies)
3. [Setup Instructions](#setup-instructions)
4. [Environment Variables](#environment-variables)
5. [Database Setup](#database-setup)
6. [Running the Application](#running-the-application)
7. [Running Tests](#running-tests)
8. [Rate Limiting](#rate-limiting)
9. [Logging](#logging)
10. [Error Handling](#error-handling)
11. [Project Structure](#project-structure)

* * * * *

1\. Overview
------------

This project is a Node.js REST API built with **Express**, **Prisma**, and **PostgreSQL**. It includes user authentication (JWT), route protection, rate limiting, and logging. Supports both cookie-based and bearer token authentication.

* * * * *

2\. Technologies
----------------

- **Node.js** (v18.x)
- **Express.js**
- **Prisma ORM**
- **PostgreSQL**
- **TypeScript**
- **Vitest** (testing)
- **Supertest** (HTTP testing)
- **Helmet** (security)
- **express-rate-limit** (rate limiting)
- **JWT** (authentication)

* * * * *

3\. Setup Instructions
----------------------

### Prerequisites

- **Node.js v18 or higher**
- **PostgreSQL**

### Install Dependencies

bash

Copy code

`npm install`

* * * * *

4\. Environment Variables
-------------------------

Create a `.env` file with:

env

Copy code

`DATABASE_URL=postgresql://user:password@localhost:6900/trpc_prisma
JWT_SECRET=your_jwt_secret
JWT_EXPIRES_IN=90d
JWT_COOKIE_EXPIRES_IN=90
NODE_ENV=development
PORT=3000`

* * * * *

5\. Database Setup
------------------

1. Push the schema:

    bash

    Copy code

    `npx prisma db push`

2. Generate Prisma client:

    bash

    Copy code

    `npx prisma generate`

* * * * *

6\. Running the Application
---------------------------

Start the app locally:

bash

Copy code

`npm run dev`

Access at `http://localhost:3000`.

* * * * *

7\. Running Tests
-----------------

Run the test suite using Vitest:

bash

Copy code

`npm run test`

* * * * *

8\. Rate Limiting
-----------------

Rate limiting is enabled to restrict requests to 100 per 10 minutes per IP. Adjust in `app.ts`:

ts

Copy code

`const limiter = rateLimit({
  max: 100,
  windowMs: 10 * 60 * 1000,
  message: 'Too many requests, try again later.',
});`

* * * * *

9\. Logging
-----------

Logs include:

- Request details (HTTP method, URL, IP)
- User actions (signup, login)
- Error logs for debugging

* * * * *

10\. Error Handling
-------------------

A global error handler captures all unhandled errors, including Prisma and API errors.

ts

Copy code

`app.use(globalErrorHandler);`

Custom `AppError` class for operational errors:

ts

Copy code

`class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status =`${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
  }
}`

* * * * *

11\. Project Structure
----------------------

bash

Copy code

`/src
  /app.ts            # Main app setup
  /prisma.ts         # Prisma client setup
  /utils             # Utility functions (e.g., error handling)
  /tests             # Unit and integration tests
/prisma               # Prisma schema and migrations
/types                # Custom TypeScript types
/logs                 # Log files`

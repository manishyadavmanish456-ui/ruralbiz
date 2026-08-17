# RuralBiz API

Production backend for the RuralBiz retailer, wholesaler and supplier platform.

## Features

- Secure user authentication
- Retailer, wholesaler and supplier roles
- Product management
- Wholesaler inventory management
- Retailer orders
- Automatic stock deduction after order confirmation
- Stock movement history
- Digital Khata / ledger
- PostgreSQL database
- JWT authentication
- Automatic database table initialization

## Render Configuration

Runtime:
Node

Build Command:
npm install

Start Command:
npm start

## Environment Variables

The Render service requires:

DATABASE_URL

JWT_SECRET

NODE_ENV=production

Never put passwords, database URLs, JWT secrets, OTP secrets or API keys inside GitHub source files.

## Database

The application automatically creates the required PostgreSQL tables when the server starts.

## Health Check

The API provides:

/health

A successful response looks like:

{"ok":true,"db":true}

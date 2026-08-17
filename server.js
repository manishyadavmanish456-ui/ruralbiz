import express from "express";
import cors from "cors";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";

const { Pool } = pg;

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET = process.env.JWT_SECRET;

if (!process.env.DATABASE_URL || !SECRET) {
  console.error("Missing DATABASE_URL or JWT_SECRET");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

app.use(helmet());
app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));

const schema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  phone TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('retailer','wholesaler','supplier')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  sku TEXT,
  unit TEXT NOT NULL DEFAULT 'piece',
  price NUMERIC(12,2) NOT NULL DEFAULT 0,
  stock NUMERIC(14,3) NOT NULL DEFAULT 0,
  owner_id UUID NOT NULL REFERENCES users(id),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  retailer_id UUID NOT NULL REFERENCES users(id),
  wholesaler_id UUID NOT NULL REFERENCES users(id),
  supplier_id UUID REFERENCES users(id),
  total NUMERIC(12,2) NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS order_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id UUID NOT NULL REFERENCES products(id),
  quantity NUMERIC(14,3) NOT NULL CHECK (quantity > 0),
  unit_price NUMERIC(12,2) NOT NULL
);

CREATE TABLE IF NOT EXISTS stock_movements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id UUID NOT NULL REFERENCES products(id),
  quantity NUMERIC(14,3) NOT NULL,
  reason TEXT NOT NULL,
  user_id UUID NOT NULL REFERENCES users(id),
  order_id UUID REFERENCES orders(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ledger_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  party_id UUID NOT NULL REFERENCES users(id),
  created_by UUID NOT NULL REFERENCES users(id),
  entry_type TEXT NOT NULL CHECK (entry_type IN ('credit','debit')),
  amount NUMERIC(12,2) NOT NULL CHECK (amount >= 0),
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_products_owner
ON products(owner_id);

CREATE INDEX IF NOT EXISTS idx_orders_retailer
ON orders(retailer_id);

CREATE INDEX IF NOT EXISTS idx_orders_wholesaler
ON orders(wholesaler_id);

CREATE INDEX IF NOT EXISTS idx_ledger_party
ON ledger_entries(party_id);
`;

async function initializeDatabase() {
  const statements = schema
    .split(";")
    .map((sql) => sql.trim())
    .filter(Boolean);

  for (const sql of statements) {
    await pool.query(sql);
  }

  console.log("Database schema ready");
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      name: user.name,
      role: user.role
    },
    SECRET,
    { expiresIn: "7d" }
  );
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  const token = header.substring(7);

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

function allowRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Not allowed"
      });
    }

    next();
  };
}

/* Health check */

app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      db: true
    });
  } catch {
    res.status(503).json({
      ok: false,
      db: false
    });
  }
});

/* Database status */

app.get("/api/status", async (_req, res) => {
  try {
    const result = await pool.query(
      "SELECT COUNT(*)::int AS users FROM users"
    );

    res.json({
      ok: true,
      database: true,
      users: result.rows[0].users
    });
  } catch {
    res.status(503).json({
      ok: false,
      error: "Database not initialized"
    });
  }
});

/* Register */

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      phone,
      password,
      role = "retailer"
    } = req.body;

    if (!name || !phone || !password) {
      return res.status(400).json({
        error: "Name, phone and password are required"
      });
    }

    if (!["retailer", "wholesaler", "supplier"].includes(role)) {
      return res.status(400).json({
        error: "Invalid role"
      });
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE phone = $1",
      [phone]
    );

    if (existing.rowCount) {
      return res.status(409).json({
        error: "Phone already registered"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users
       (name, phone, password_hash, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, phone, role`,
      [name, phone, passwordHash, role]
    );

    const user = result.rows[0];

    res.status(201).json({
      user,
      token: createToken(user)
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Registration failed"
    });
  }
});

/* Login */

app.post("/api/auth/login", async (req, res) => {
  try {
    const { phone, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE phone = $1",
      [phone]
    );

    if (
      !result.rowCount ||
      !(await bcrypt.compare(
        password || "",
        result.rows[0].password_hash
      ))
    ) {
      return res.status(401).json({
        error: "Invalid phone or password"
      });
    }

    const user = result.rows[0];

    const safeUser = {
      id: user.id,
      name: user.name,
      phone: user.phone,
      role: user.role
    };

    res.json({
      user: safeUser,
      token: createToken(safeUser)
    });

  } catch {
    res.status(500).json({
      error: "Login failed"
    });
  }
});

/* Products */

app.get("/api/products", authenticate, async (_req, res) => {
  const result = await pool.query(
    `SELECT id, name, sku, unit, price,
            stock, owner_id, active
     FROM products
     WHERE active = true
     ORDER BY name`
  );

  res.json(result.rows);
});

/* Add product */

app.post(
  "/api/products",
  authenticate,
  allowRoles("wholesaler", "supplier"),
  async (req, res) => {
    try {
      const {
        name,
        sku,
        unit = "piece",
        price = 0,
        stock = 0
      } = req.body;

      if (!name) {
        return res.status(400).json({
          error: "Product name is required"
        });
      }

      const result = await pool.query(
        `INSERT INTO products
         (name, sku, unit, price, stock, owner_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [
          name,
          sku || null,
          unit,
          Number(price),
          Number(stock),
          req.user.id
        ]
      );

      res.status(201).json(result.rows[0]);

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Product creation failed"
      });
    }
  }
);

/* Manual stock update */

app.patch(
  "/api/products/:id/stock",
  authenticate,
  allowRoles("wholesaler", "supplier"),
  async (req, res) => {
    const quantity = Number(req.body.quantity);

    if (!Number.isFinite(quantity)) {
      return res.status(400).json({
        error: "Valid quantity required"
      });
    }

    const result = await pool.query(
      `UPDATE products
       SET stock = stock + $1,
           updated_at = NOW()
       WHERE id = $2
       AND owner_id = $3
       RETURNING *`,
      [
        quantity,
        req.params.id,
        req.user.id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Product not found"
      });
    }

    await pool.query(
      `INSERT INTO stock_movements
       (product_id, quantity, reason, user_id)
       VALUES ($1, $2, 'manual_adjustment', $3)`,
      [
        req.params.id,
        quantity,
        req.user.id
      ]
    );

    res.json(result.rows[0]);
  }
);

/* Create order */

app.post(
  "/api/orders",
  authenticate,
  allowRoles("retailer"),
  async (req, res) => {
    const {
      wholesalerId,
      items = []
    } = req.body;

    if (!wholesalerId || !items.length) {
      return res.status(400).json({
        error: "Wholesaler and items are required"
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      let total = 0;

      for (const item of items) {
        const product = await client.query(
          `SELECT price, stock
           FROM products
           WHERE id = $1
           AND owner_id = $2
           AND active = true
           FOR UPDATE`,
          [
            item.productId,
            wholesalerId
          ]
        );

        if (
          !product.rowCount ||
          Number(item.quantity) <= 0 ||
          Number(item.quantity) >
            Number(product.rows[0].stock)
        ) {
          throw new Error(
            "Product unavailable or insufficient stock"
          );
        }

        total +=
          Number(product.rows[0].price) *
          Number(item.quantity);
      }

      const order = await client.query(
        `INSERT INTO orders
         (retailer_id, wholesaler_id, total, status)
         VALUES ($1, $2, $3, 'pending')
         RETURNING *`,
        [
          req.user.id,
          wholesalerId,
          total
        ]
      );

      for (const item of items) {
        const product = await client.query(
          "SELECT price FROM products WHERE id = $1",
          [item.productId]
        );

        await client.query(
          `INSERT INTO order_items
           (order_id, product_id, quantity, unit_price)
           VALUES ($1, $2, $3, $4)`,
          [
            order.rows[0].id,
            item.productId,
            Number(item.quantity),
            product.rows[0].price
          ]
        );
      }

      await client.query("COMMIT");

      res.status(201).json(order.rows[0]);

    } catch (error) {
      await client.query("ROLLBACK");

      res.status(400).json({
        error: error.message
      });

    } finally {
      client.release();
    }
  }
);

/* Orders */

app.get(
  "/api/orders",
  authenticate,
  async (req, res) => {
    const column =
      req.user.role === "retailer"
        ? "retailer_id"
        : req.user.role === "wholesaler"
        ? "wholesaler_id"
        : "supplier_id";

    const result = await pool.query(
      `SELECT *
       FROM orders
       WHERE ${column} = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  }
);

/* Confirm order and reduce stock */

app.post(
  "/api/orders/:id/confirm",
  authenticate,
  allowRoles("wholesaler"),
  async (req, res) => {
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const order = await client.query(
        `SELECT *
         FROM orders
         WHERE id = $1
         AND wholesaler_id = $2
         FOR UPDATE`,
        [
          req.params.id,
          req.user.id
        ]
      );

      if (
        !order.rowCount ||
        order.rows[0].status !== "pending"
      ) {
        throw new Error(
          "Order not found or already processed"
        );
      }

      const items = await client.query(
        "SELECT * FROM order_items WHERE order_id = $1",
        [req.params.id]
      );

      for (const item of items.rows) {
        const updated = await client.query(
          `UPDATE products
           SET stock = stock - $1,
               updated_at = NOW()
           WHERE id = $2
           AND owner_id = $3
           AND stock >= $1
           RETURNING id`,
          [
            item.quantity,
            item.product_id,
            req.user.id
          ]
        );

        if (!updated.rowCount) {
          throw new Error(
            "Insufficient stock"
          );
        }

        await client.query(
          `INSERT INTO stock_movements
           (product_id, quantity, reason, user_id, order_id)
           VALUES ($1, $2, 'order_confirmed', $3, $4)`,
          [
            item.product_id,
            -item.quantity,
            req.user.id,
            req.params.id
          ]
        );
      }

      const updatedOrder = await client.query(
        `UPDATE orders
         SET status = 'confirmed',
             updated_at = NOW()
         WHERE id = $1
         RETURNING *`,
        [req.params.id]
      );

      await client.query("COMMIT");

      res.json(updatedOrder.rows[0]);

    } catch (error) {
      await client.query("ROLLBACK");

      res.status(400).json({
        error: error.message
      });

    } finally {
      client.release();
    }
  }
);

/* Digital Khata */

app.get(
  "/api/ledger/:partyId",
  authenticate,
  async (req, res) => {
    const result = await pool.query(
      `SELECT id,
              entry_type,
              amount,
              note,
              created_at
       FROM ledger_entries
       WHERE party_id = $1
       ORDER BY created_at DESC`,
      [req.params.partyId]
    );

    res.json(result.rows);
  }
);

app.post(
  "/api/ledger",
  authenticate,
  allowRoles("wholesaler"),
  async (req, res) => {
    const {
      partyId,
      entryType,
      amount,
      note
    } = req.body;

    if (
      !partyId ||
      !["credit", "debit"].includes(entryType) ||
      !Number.isFinite(Number(amount))
    ) {
      return res.status(400).json({
        error: "Invalid ledger entry"
      });
    }

    const result = await pool.query(
      `INSERT INTO ledger_entries
       (party_id, created_by, entry_type, amount, note)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [
        partyId,
        req.user.id,
        entryType,
        Number(amount),
        note || null
      ]
    );

    res.status(201).json(result.rows[0]);
  }
);

/* 404 */

app.use((_req, res) => {
  res.status(404).json({
    error: "Not found"
  });
});

/* Start only after database is ready */

async function startServer() {
  try {
    const statements = schema
      .split(";")
      .map((sql) => sql.trim())
      .filter(Boolean);

    for (const sql of statements) {
      await pool.query(sql);
    }

    console.log("Database schema ready");

    app.listen(PORT, () => {
      console.log(
        `RuralBiz API listening on ${PORT}`
      );
    });

  } catch (error) {
    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  }
}

startServer();

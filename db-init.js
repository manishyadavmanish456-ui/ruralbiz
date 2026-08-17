import fs from "fs";
export async function ensureSchema(pool){
  const sql=fs.readFileSync(new URL("./schema.sql", import.meta.url),"utf8");
  for(const statement of sql.split(";").map(s=>s.trim()).filter(Boolean)) await pool.query(statement);
}

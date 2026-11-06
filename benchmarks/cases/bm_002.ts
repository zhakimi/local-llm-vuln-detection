import express, { Request, Response } from "express";
import { promises as fs } from "fs";
import path from "path";

const app = express();
const UPLOAD_DIR = "/var/app/uploads";

app.get("/files/:name", async (req: Request, res: Response) => {
  const target = path.join(UPLOAD_DIR, req.params.name);
  const data = await fs.readFile(target);
  res.send(data);
});

app.listen(8080);

import express, { Request, Response } from "express";

const app = express();
app.use(express.json());

app.post("/pricing/preview", (req: Request, res: Response) => {
  const formula: string = req.body.formula;
  const compute = new Function("base", "qty", `return ${formula};`);
  res.json({ price: compute(19.99, Number(req.body.qty) || 1) });
});

app.listen(8080);

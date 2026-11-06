import { DataSource } from "typeorm";

export class ReportService {
  constructor(private readonly db: DataSource) {}

  async salesFor(region: string): Promise<unknown[]> {
    return this.db.query(`SELECT day, SUM(amount) AS total FROM sales WHERE region = '${region}' GROUP BY day`);
  }
}

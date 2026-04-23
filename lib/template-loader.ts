import { promises as fs } from "node:fs";
import path from "node:path";
import type { TemplateMap } from "@/lib/email-alert-generator";

export async function loadTemplates(): Promise<TemplateMap> {
  const templatesDir = path.join(process.cwd(), "templates");
  const entries = await fs.readdir(templatesDir, { withFileTypes: true });
  const templateFiles = entries.filter((entry) => entry.isFile() && entry.name.endsWith(".txt"));
  const templates = await Promise.all(
    templateFiles.map(async (entry) => {
      const content = await fs.readFile(path.join(templatesDir, entry.name), "utf8");
      return [entry.name, content] as const;
    })
  );

  return Object.fromEntries(templates);
}

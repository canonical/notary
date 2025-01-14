/** @type {import('next').NextConfig} */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const version = fs.readFileSync(path.join(__dirname, '../version/VERSION'), 'utf8').trim();

const nextConfig = {
    output: "export",
    env: {
        VERSION: version
    }
};

export default nextConfig;

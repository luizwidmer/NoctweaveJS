import { readFileSync, writeFileSync } from "node:fs";
import * as png2icons from "png2icons";

const source = readFileSync(new URL("../assets/app-icon.png", import.meta.url));
const icns = png2icons.createICNS(source, png2icons.BICUBIC2, 0);
const ico = png2icons.createICO(source, png2icons.BICUBIC2, 0, false, true);

if (!icns || !ico) {
  throw new Error("Failed to generate desktop icon formats.");
}

writeFileSync(new URL("../assets/app-icon.icns", import.meta.url), Uint8Array.from(icns));
writeFileSync(new URL("../assets/app-icon.ico", import.meta.url), Uint8Array.from(ico));

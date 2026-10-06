import { createRequire } from 'node:module';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Sharp is a development-only renderer. Committed assets need no build dependency.
const require = createRequire(process.argv[2]
  ? resolve(process.argv[2], '..', 'package.json') : import.meta.url);
const sharp = require('sharp');
const directory = dirname(fileURLToPath(import.meta.url));
const icon = await readFile(resolve(directory, 'etl-icon.svg'));
const sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256];
const frames = await Promise.all(sizes.map(size => sharp(icon, {density:384})
  .resize(size,size).png().toBuffer()));
const header = Buffer.alloc(6 + sizes.length * 16);
header.writeUInt16LE(1,2); header.writeUInt16LE(sizes.length,4);
let offset = header.length;
frames.forEach((frame,index) => {
  const entry = 6 + index * 16;
  header[entry] = header[entry+1] = sizes[index] === 256 ? 0 : sizes[index];
  header.writeUInt16LE(1,entry+4); header.writeUInt16LE(32,entry+6);
  header.writeUInt32LE(frame.length,entry+8); header.writeUInt32LE(offset,entry+12);
  offset += frame.length;
});
await writeFile(resolve(directory,'etl.ico'),Buffer.concat([header,...frames]));
await writeFile(resolve(directory,'etl-icon.png'),frames.at(-1));
for (const variant of ['black','white']) {
  const logo = await readFile(resolve(directory,`etl-logo-${variant}.svg`));
  await sharp(logo,{density:288}).png().toFile(resolve(directory,`etl-logo-${variant}.png`));
  const mark = (await readFile(resolve(directory,'etl-mark.svg'),'utf8'))
    .replace('currentColor',variant === 'black' ? '#151918' : '#f7f8f7');
  await sharp(Buffer.from(mark),{density:384}).resize(110,110).png()
    .toFile(resolve(directory,`wizard-${variant}.png`));
  const banner = `<svg xmlns="http://www.w3.org/2000/svg" width="404" height="772" viewBox="0 0 202 386"><rect width="202" height="386" fill="${variant === 'black' ? '#ffffff' : '#202020'}"/><g transform="translate(53 145) scale(1.5)">${mark.replace(/<\/?svg[^>]*>/g,'')}</g></svg>`;
  await sharp(Buffer.from(banner)).png()
    .toFile(resolve(directory,`wizard-banner-${variant}.png`));
}
const [black,white] = await Promise.all(['black','white'].map(variant =>
  sharp(resolve(directory,`etl-logo-${variant}.png`)).resize(300,140).toBuffer()));
await sharp({create:{width:960,height:360,channels:4,background:'#ffffff'}})
  .composite([
    {input:Buffer.from('<svg width="480" height="360"><rect width="480" height="360" fill="#050505"/></svg>'),left:480,top:0},
    {input:black,left:80,top:96},{input:white,left:560,top:96},
  ]).png().toFile(resolve(directory,'etl-logo-preview.png'));
console.log(`Rendered ETL logos and ${sizes.length} icon sizes.`);

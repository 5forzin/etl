# ETL logo

The symbol is a solid E with three diagonal terminals. Its simple silhouette
works in black or white and remains legible at tray-icon sizes. Use black on
light backgrounds and white on dark backgrounds. The
wordmark uses outlined Inter Semi Bold, so SVGs need no installed font.

`etl-mark.svg` inherits `currentColor`. `etl-icon.svg` adds a dark tile and a subtle
border so the application icon remains visible on either background. `etl.ico`
contains 16, 20, 24, 32, 40, 48, 64, 128 and 256 pixel images.

The SVGs are the editable sources.
Inter's [license](../../native/windows/assets/LICENSE-Inter.txt) applies to its
letterforms.

To regenerate PNG and ICO outputs, install Sharp in an ignored tools directory
and pass that directory's `node_modules` path:

~~~sh
npm install --prefix build/asset-tools sharp
node assets/brand/render.mjs build/asset-tools/node_modules
~~~

The committed graphics are used directly by normal client and installer builds.

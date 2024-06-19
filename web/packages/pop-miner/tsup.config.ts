/**
 * Copyright (c) 2024 Hemi Labs, Inc.
 * Use of this source code is governed by the MIT License,
 * which can be found in the LICENSE file.
 */

import { defineConfig } from 'tsup';

export default defineConfig((options) => ({
  entry: ['src/browser/**', 'src/types.ts'],
  outDir: 'dist',
  format: ['esm'],
  publicDir: 'wasm',
  shims: true,
  dts: true,
  clean: true,
  minify: !options.watch,
  sourcemap: Boolean(options.watch),
  watch: options.watch,
}));

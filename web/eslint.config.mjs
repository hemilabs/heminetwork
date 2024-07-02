/**
 * Copyright (c) 2024 Hemi Labs, Inc.
 * Use of this source code is governed by the MIT License,
 * which can be found in the LICENSE file.
 */

import globals from 'globals';
import pluginJs from '@eslint/js';
import tseslint from 'typescript-eslint';
import pluginTSDoc from 'eslint-plugin-tsdoc';

export default [
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {
    plugins: {
      pluginTSDoc,
    },
  },
];

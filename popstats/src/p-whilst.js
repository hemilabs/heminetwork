/**
 * Copyright (c) 2024 Hemi Labs, Inc.
 * Use of this source code is governed by the MIT License,
 * which can be found in the LICENSE file.
 */

// Slightly improved version of https://github.com/sindresorhus/p-whilst
async function pWhilst(condition, action, initialValue) {
  const loop = async function (actionResult) {
    if (await condition(actionResult)) {
      return loop(await action(actionResult));
    }

    return actionResult;
  };

  return loop(await initialValue);
}

export default pWhilst;

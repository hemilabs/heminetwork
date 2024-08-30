/**
 * Copyright (c) 2024 Hemi Labs, Inc.
 * Use of this source code is governed by the MIT License,
 * which can be found in the LICENSE file.
 */

// Slightly improved version of https://github.com/sindresorhus/p-do-whilst
// Also see https://github.com/sindresorhus/p-do-whilst/issues/4
async function pDoWhilst(action, condition, initialValue) {
  const actionResult = await action(await initialValue);

  if (await condition(actionResult)) {
    return pDoWhilst(action, condition, actionResult);
  }

  return actionResult;
}

export default pDoWhilst;

/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

export function trackOrder () {
  return (req: Request, res: Response) => {
    // Truncate id to avoid unintentional RCE
    const id = !utils.isChallengeEnabled(challenges.reflectedXssChallenge) ? String(req.params.id).replace(/[^\w-]+/g, '') : utils.trunc(req.params.id, 60)

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })
    db.ordersCollection.find({
      selector: { orderId: id }
    }).then((result: any) => {
      const order = result.docs
      const jsonResult = utils.queryResultToJson(order)
      challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => jsonResult.data.length > 1)
      if (jsonResult.data[0] === undefined) {
        jsonResult.data[0] = { orderId: id }
      }
      res.json(jsonResult)
    }).catch(() => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}

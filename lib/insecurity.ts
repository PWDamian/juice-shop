/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import { expressjwt } from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */
// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error
// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC30V5VECbcOlzm
CyIo78WoxPeG4xz4V2DlqMTPzWkL4vdIcs+eChlJuVRWpAnaXXY/jL7LjM7GFLb0
jqHOCHR9PJVjy1XjvOpi1ajWXCsF86+ARBjmxqNXz5DxC1IyPGXAFyP3jxB6tQxd
iG30E6O4pf2d67llQVs/hxaLe4EkJKf/1P2x+9KTzaCfOSpwKEBO0CV3xUe5KdYP
IvdH87m7/djEvOW3k+tAnJCACYtokea1ycwU/6/aG/7udfiWRZSOx03G2MiHjbVz
pjYDFvSAWn55pHQTw8ArGwawls6GF0GYkdTxrPRRh9kfZmiZw+daW/maxvGeDH7o
CD2ywwzXAgMBAAECggEAWznYNCUg9Bku86hA2soscZbXNaVPQlyzJSc+Dddms9R/
XwBD0641YKZOmfUtQqcxwVZLdl+6Wwn6xqJm4QbHMUQ4698FEFI4jLZ25XO2kmyf
A+xH43hfpnvH9ijlMTNSWCPj4L+qsQtbSKwlzYVVspUGqjJLv1nRPFUBtlWkANgs
OVusGu8a5Ul0l9ZAbXPwa2bcAcrQil3XJMIO8ldOmb92lXnCvpjfiiL5ujAOHEr/
I/aLNPlr2OnJJSkhPJZqX81bbAN8VR9y6hKfGQ5jOhR2+9ooSn7ZqyVwjNTcDhdA
GX1yMVQJcg9KesaLz2qeKrl5juRS8/DGSL8Is6AZ2QKBgQDsrXryTAuQ/zn4LjJP
4LA5PXctWXlcFdWG3tO9jxkmjpwwgYuzghHV+5Dz1XSU0FWwFWOncuavC/fLkULx
YCW34UMZi05gsYsHV5eXQKSa5WU8EX61GkruIcp6aBu9scdZxCwzhTQEMl7HUr+v
Ry2At2SCWtx99z3JRXj4pjO0AwKBgQDG0yC5p4pggoKoaGC+ryNqsc0Fnp/mZwcR
iA9pKh8ZYg2F4AhCDN2w6H7hxXJmYcKU2Vrm8/cq7XBZ0Ez9tKS/Bso4tUu8KuRC
SE+PtILsgOZoFQmvaqFcrIQo3zZms27gPoP/tevq2vgj1MAMOgz2jX9sy1Vc7SLE
xD6U+PiNnQKBgQCmt+lURpcbM35NQZV1SQw5tf9+dXmUkVjRYaN78xI/Y9PII2ka
MPSJbGUGLgWqUjsaB2ckbD7tbZvGzPN//j9zkP1oQAYc/NO3f08sX3/UEOVH8/by
cav4pNrxcOahsFqB9DtCq4Eht62l8LdQK+50rjrhzElnfkMKxaJaXREsqwKBgQCf
se6kD9TOZaVKXOPv5L4+sWbqb5khN3lu9GjkYCewfJg+Ak6/tpPNx0A6WRvk7fqb
EeW4gRXyzdmi2fMtCA4XPP3qBHw7O/ww3OHCnAtYqMPnr5Yi5jOLOym/pmGMpeyV
gsEE/3rpHU2XggdrCqlk0wwZN0xuIi39+14Ey+Df5QKBgHvTjeXjrZAyl+8+3QJB
jHB3UDmtKVTG75gYakbAfYD/nNMHw3rbiZxOrgPNB1bY9uPCWdRNRLZKcytB5irt
MmaoZ6VxtUYmS2pZzH5EKIE4wpQOZJtSSF8wGejWjkAKVi1qdmqKwXBtN1N8urLF
MxKJuXeP0uiS6MYv4A5naJTJ
-----END PRIVATE KEY-----
`

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

export const isAuthorized = () => expressjwt(({ secret: publicKey, algorithms: ['RS256'] }) as any)
export const denyAll = () => expressjwt({ secret: '' + Math.random(), algorithms: ['RS256'] } as any)
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token: string) => token ? jws.verify(token, 'RS256', publicKey) : false
export const decode = (token: string) => { return jws.decode(token)?.payload }

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1]
      return parseInt(discount)
    }
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl) // vuln-code-snippet vuln-line redirectChallenge
  }
  return allowed
}
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', privateKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: any) {
      res.status(401).json({ status: 'error', message: error })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token) {
    jwt.verify(token, publicKey, (err: Error | null, decoded: any) => {
      if (err === null) {
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token)
        }
      }
    })
  }
  next()
}

import jwt from 'jsonwebtoken'
import { session } from './../session/session.js'

const JWTSignature = process.env.JWT_SIGNATURE

async function logUserOut(request, reply) {
  try {
    if (request?.cookies?.refreshToken) {
      const { refreshToken } = request.cookies

      // Decode refresh token
      const { sessionToken } = jwt.verify(refreshToken, JWTSignature)

      // Delete database record for session
      await session.deleteOne({ sessionToken })
    }
    // Remove cookie
    reply.clearCookie('refreshToken').clearCookie('accessToken')
  } catch (e) {
    console.error(e)
  }
}

export { logUserOut }

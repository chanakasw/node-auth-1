import bcrypt from 'bcryptjs'
import { user } from './../user/user.js'

const { compare } = bcrypt

async function authorizeUser(email, password) {
  // Lookup user
  const userData = await user.findOne({ 'email.address': email })

  // Get user password
  const savedPassword = userData.password

  // Compare password the one in database
  const isAuthorized = await compare(password, savedPassword)

  // Return boolean of if password is correct
  return { isAuthorized, userId: userData._id }
}

export { authorizeUser }

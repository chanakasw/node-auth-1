import { client } from './../db.js'

const user = client.db('test').collection('user')
// user.createIndex({ 'email.address': 1 })

export { user }

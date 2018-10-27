module.exports = express => {
  const api = express.Router()

  require('./auth')(api)

  return api
}

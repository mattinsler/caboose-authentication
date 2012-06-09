caboose = Caboose.exports
util = Caboose.util
logger = Caboose.logger

unauthorized = (realm) ->
  @set_headers('Content-Type': 'text/plain', 'WWW-Authenticate': "Basic realm=#{realm}")
  @unauthorized(new Error('Authorization Required'))

module.exports =
  'caboose-plugin': {
    install: (util, logger) ->
      logger.title 'Running installer for caboose-authentication'
    
    initialize: ->
      # logger.title 'Initializing caboose-authentication'
      
      if Caboose?
        caboose.controller.Builder.add_plugin 'http_basic_authenticate_with',
          name: 'http_basic_authenticate_with'
          execute: (opts = {}) ->
            throw new Error('http_basic_authenticate_with requires username and password options') unless opts.username? and opts.password?
            opts.realm ||= 'Basic'

            @before_action (next) ->
              return unauthorized.call(@, opts.realm) unless @headers.authorization?

              matches = /^basic ([A-Za-z0-9=]+)$/i.exec(@headers.authorization)
              return unauthorized.call(@, opts.realm) unless matches?

              creds = new Buffer(matches[1], 'base64').toString('utf8').split(':')
              return unauthorized.call(@, opts.realm) unless creds.length is 2 and creds[0] is opts.username and creds[1] is opts.password

              next()
  }

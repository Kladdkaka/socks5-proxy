const net = require('net')

const RFC1928 = {
  HANDSHAKE: {
    REQUEST: {
      VER: 0x05,
      NMETHODS: undefined, // should i use number?
      METHODS: {
        NO_AUTHENTICATION_REQUIRED: 0x00,
        GSSAPI: 0x01,
        USERNAME_PASSWORD: 0x02,
        NO_ACCEPTABLE_METHODS: 0xFF
      }
    },
    RESPONSE: {
      VER: 0x05,
      METHOD: {
        NO_AUTHENTICATION_REQUIRED: 0x00,
        GSSAPI: 0x01,
        USERNAME_PASSWORD: 0x02,
        NO_ACCEPTABLE_METHODS: 0xFF
      }
    }
  },
  REQUEST: {
        /*
            o  VER    protocol version: X'05'
            o  CMD
              o  CONNECT X'01'
              o  BIND X'02'
              o  UDP ASSOCIATE X'03'
            o  RSV    RESERVED
            o  ATYP   address type of following address
              o  IP V4 address: X'01'
              o  DOMAINNAME: X'03'
              o  IP V6 address: X'04'
            o  DST.ADDR desired destination address
            o  DST.PORT desired destination port in network octet order
        */
    VER: 0x05,
    CMD: {
      CONNECT: 0x01,
      BIND: 0x02,
      UDP_ASSOCIATE: 0x03
    },
    RSV: undefined, // i think?
    ATYP: {
      IPV4: 0x01,
      DOMAIN: 0x03,
      IPV6: 0x04
    },
    DST: {
      ADDR: undefined,
      PORT: undefined
    }
  },
  RESPONSE: {
        /*
            o  VER    protocol version: X'05'
            o  REP    Reply field:
                o  X'00' succeeded
                o  X'01' general SOCKS server failure
                o  X'02' connection not allowed by ruleset
                o  X'03' Network unreachable
                o  X'04' Host unreachable
                o  X'05' Connection refused
                o  X'06' TTL expired
                o  X'07' Command not supported
                o  X'08' Address type not supported
                o  X'09' to X'FF' unassigned
            o  RSV    RESERVED
            o  ATYP   address type of following address
                o  IP V4 address: X'01'
                o  DOMAINNAME: X'03'
                o  IP V6 address: X'04'
            o  BND.ADDR       server bound address
            o  BND.PORT       server bound port in network octet order

            Fields marked RESERVED (RSV) must be set to X'00'.
        */
    VER: 0x05,
    REP: {
      SUCCEEDED: 0x00,
      GENERAL_SOCKS_SERVER_FAILURE: 0x01,
      CONNECTION_NOT_ALLOWED_BY_RULESET: 0x02,
      NETWORK_UNREACHABLE: 0x03,
      HOST_UNREACHABLE: 0x04,
      CONNECTION_REFUSED: 0x05,
      TTL_EXPIRED: 0x06,
      COMMAND_NOT_SUPPORTED: 0x07,
      ADDRESS_TYPE_NOT_SUPPORTED: 0x08
    },
    RSV: 0x00,
    ATYP: {
      IPV4: 0x01,
      DOMAIN: 0x03,
      IPV6: 0x04
    },
    BND: {
      ADDR: undefined, // set yourself?
      PORT: undefined
    }
  }
}

function Server (options) {
  const self = this

  self.server = net.createServer(socket => {
    socket.on('error', error => {
      console.error('error', error)
            // handle
    })

    const end = code => {
      const responseBuffer = Buffer.from([RFC1928.RESPONSE.VER, code])

      // console.log(responseBuffer)

      try {
        socket.end(responseBuffer)
      } catch (error) {
        console.error(error)
        socket.destroy()
      }
    }

    const connect = buffer => {
      let args = {
        ver: buffer.readInt8(0),
        cmd: buffer.readInt8(1),
        rsv: buffer.readInt8(2),
        atyp: buffer.readInt8(3)
      }

      // console.log(args)

      if (args.ver !== RFC1928.RESPONSE.VER) return end(RFC1928.RESPONSE.REP.GENERAL_SOCKS_SERVER_FAILURE)

      args.dst = {}
      args.addr = {}

      let last

      switch (args.atyp) {
        case RFC1928.REQUEST.ATYP.IPV4:
          last = 8

          args.addr.buf = buffer.slice(4, last)

          args.dst.addr = Array.from(args.addr.buf).join('.')
          // console.log(args)
          break
        case RFC1928.REQUEST.ATYP.DOMAIN:
          args.addr.size = buffer.readInt8(4)

          last = 5 + args.addr.size

          args.addr.buf = buffer.slice(5, last)

          args.dst.addr = args.addr.buf.toString()
          // console.log(args)
          break
        case RFC1928.REQUEST.ATYP.IPV6:
          last = 20
          args.addr.buf = buffer.slice(4, last)

          args.addr.parts = {}

          args.addr.parts.a = args.addr.buf.readInt32BE(0)
          args.addr.parts.b = args.addr.buf.readInt32BE(4)
          args.addr.parts.c = args.addr.buf.readInt32BE(8)
          args.addr.parts.d = args.addr.buf.readInt32BE(12)

          for (const key of [Object.keys(args.addr.parts)]) {
            const value = args.addr.parts[key]

            args.dst.addr.push(((value & 0xffff0000) >> 16).toString(16))
            args.dst.addr.push(((value & 0xffff)).toString(16))
          }

          args.dst.addr = args.dst.addr.join(':')
          break
        default:
          return end(RFC1928.RESPONSE.REP.ADDRESS_TYPE_NOT_SUPPORTED)
      }

      args.dst.port = buffer.readInt16BE(last)

      // console.log('ayy')
      // console.log(args)

      switch (args.cmd) {
        case RFC1928.REQUEST.CMD.CONNECT:
          const destination = net.createConnection(args.dst.port, args.dst.addr, () => {
            const responseBuffer = Buffer.alloc(buffer.length, 0)

            // console.log(responseBuffer)

            let i = 0
            i = responseBuffer.writeInt8(RFC1928.RESPONSE.VER, i)
            i = responseBuffer.writeInt8(RFC1928.RESPONSE.REP.SUCCEEDED, i)
            i = responseBuffer.writeInt8(RFC1928.RESPONSE.RSV, i)
            i = responseBuffer.writeInt8(args.atyp, i)
            i += responseBuffer.copy(args.addr.buf, i)
            i = responseBuffer.writeInt16BE(args.dst.port, i)

            // console.log('res', responseBuffer)
            // console.log('req', buffer)

            socket.write(responseBuffer, () => {
              destination.pipe(socket)
              socket.pipe(destination)
            })
          })

          destination.on('connect', () => {
            const info = {
              host: args.dst.addr,
              port: args.dst.port
            }

                        // emit connection event
            console.log(info) // destination)

                        // capture and emit proxied connection data
                        /* destination.on('data', data => {
                          console.log('ello')
                          console.log(data.toString())
                        }) */
          })

          destination.on('error', error => {
            error.addr = args.dst.addr
            error.port = args.dst.port
            error.atyp = args.atyp

            console.error(error)
            console.error(error.code)

            if (error.code && error.code === 'EADDRNOTAVAIL') {
              return end(RFC1928.RESPONSE.REP.HOST_UNREACHABLE)
            }

            if (error.code && error.code === 'ECONNREFUSED') {
              return end(RFC1928.RESPONSE.REP.CONNECTION_REFUSED)
            }

            return end(RFC1928.RESPONSE.REP.NETWORK_UNREACHABLE)
          })
          break
        case RFC1928.REQUEST.CMD.BIND: // todo: implement
          return end(RFC1928.RESPONSE.REP.COMMAND_NOT_SUPPORTED)
        case RFC1928.REQUEST.CMD.UDP_ASSOCIATE: // todo: implement
          return end(RFC1928.RESPONSE.REP.COMMAND_NOT_SUPPORTED)
        default: // unknown command
          console.log(`${args.cmd.toString(16)} is not a documented command.`)
          return end(RFC1928.RESPONSE.REP.COMMAND_NOT_SUPPORTED)
      }
    }

    const handshake = buffer => {
      let args = {
        ver: buffer.readInt8(0),
        nmethods: buffer.readInt8(1),
        methods: Array.from(buffer.slice(2, 2 + buffer.readInt8(1)))
      }

      // console.log(args)

      // console.log('uwu')

      // console.log('yes', args.ver !== RFC1928.HANDSHAKE.REQUEST.VER)
      // console.log(typeof RFC1928.HANDSHAKE.REQUEST.VER)
      // console.log(typeof args.ver)
      // console.log(args.ver === RFC1928.HANDSHAKE.REQUEST.VER)

      if (args.ver !== RFC1928.HANDSHAKE.REQUEST.VER) {
        return end(RFC1928.RESPONSE.REP.GENERAL_SOCKS_SERVER_FAILURE)
      }

      // console.log('yes')

      if (!args.methods.includes(RFC1928.HANDSHAKE.REQUEST.METHODS.NO_AUTHENTICATION_REQUIRED)) {
        return end(RFC1928.HANDSHAKE.RESPONSE.METHOD.NO_ACCEPTABLE_METHODS)
      }

      // console.log('ok')

      const responseBuffer = Buffer.from([RFC1928.RESPONSE.VER, RFC1928.HANDSHAKE.RESPONSE.METHOD.NO_AUTHENTICATION_REQUIRED])

      // console.log(responseBuffer)

      socket.write(responseBuffer, () => {
        socket.once('data', connect)
      })
    }

        // handshake
    socket.once('data', handshake)
  })

  return self.server
}

module.exports = Server

new Server().listen(1080)

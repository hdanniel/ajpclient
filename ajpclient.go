package main

import (
        "bytes"
        "encoding/binary"
        "fmt"
        "net"
        "net/url"
        "os"
        "strings"
        "flag"
        "strconv"
        //"reflect"
        //"strconv"
        "compress/flate"
        "io"
        "time"
)

//constants
const AJP_HEADER_LEN int = 4

//
const SC_REQ_ACCEPT string = "\xA0\x01"
const SC_REQ_ACCEPT_CHARSET string = "\xA0\x02"
const SC_REQ_ACCEPT_ENCODING string = "\xA0\x03"
const SC_REQ_ACCEPT_LANGUAGE string = "\xA0\x04"
const SC_REQ_AUTHORIZATION string = "\xA0\x05"
const SC_REQ_CONNECTION string = "\xA0\x06"
const SC_REQ_CONTENT_TYPE string = "\xA0\x07"   // \a
const SC_REQ_CONTENT_LENGTH string = "\xA0\x08" // \b \10
const SC_REQ_COOKIE string = "\xA0\x09"         // \t
const SC_REQ_COOKIE2 string = "\xA0\x0A"        // \n
const SC_REQ_HOST string = "\xA0\x0B"           // \v
const SC_REQ_PRAGMA string = "\xA0\x0C"         // \f
const SC_REQ_REFERER string = "\xA0\x0D"        // \r
const SC_REQ_USER_AGENT string = "\xA0\x0E"

//
const SC_A_CONTEXT string = "\x01"
const SC_A_SERVLET_PATH string = "\x02"
const SC_A_REMOTE_USER string = "\x03"
const SC_A_AUTH_TYPE string = "\x04"
const SC_A_QUERY_STRING string = "\x05"
const SC_A_JVM_ROUTE string = "\x06"
const SC_A_SSL_CERT string = "\x07"
const SC_A_SSL_CIPHER string = "\x08"
const SC_A_SSL_SESSION string = "\x09"
const SC_A_REQ_ATTRIBUTE string = "\x0A"
const SC_A_SSL_KEY_SIZE string = "\x0B"
const SC_A_SECRET string = "\x0C"
const SC_A_ARE_DONE string = "\xFF"

const AJP13_SEND_BODY_CHUNK int = 3
const AJP13_SEND_HEADERS int = 4
const AJP13_END_RESPONSE int = 5
const AJP13_GET_BODY_CHUNK int = 6


func ajp_msg_append_string(ajp_msg_ptr *[]byte, ajp_string string) {
        ajp_msg := *ajp_msg_ptr
        if ajp_string == "" {
                ajp_msg = append(ajp_msg, "\xFF\xFF"...)
        } else {
                ajp_msg = append(ajp_msg, bytes_length(ajp_string)...)
                ajp_msg = append(ajp_msg, ajp_string...)
                ajp_msg = append(ajp_msg, 0x00)
        }
        *ajp_msg_ptr = ajp_msg
}

func ajp_msg_append_sc_string(ajp_msg_ptr *[]byte, ajp_string string, ajp_sc string) {
        ajp_msg := *ajp_msg_ptr
        if strings.HasPrefix(ajp_sc, "\xA0") {
                ajp_msg = append(ajp_msg, ajp_sc...)
        } else {
                ajp_msg = append(ajp_msg, bytes_length(ajp_sc)...)
                ajp_msg = append(ajp_msg, ajp_sc...)
                ajp_msg = append(ajp_msg, 0x00)
        }
        ajp_msg = append(ajp_msg, bytes_length(ajp_string)...)
        ajp_msg = append(ajp_msg, ajp_string...)
        ajp_msg = append(ajp_msg, 0x00)
        *ajp_msg_ptr = ajp_msg
}

func ajp_msg_append_attribute_string(ajp_msg_ptr *[]byte, ajp_string string, ajp_attribute string, ajp_req_attribute string) {
        ajp_msg := *ajp_msg_ptr
        ajp_msg = append(ajp_msg, ajp_attribute...)
        if ajp_req_attribute != "" {
                ajp_msg = append(ajp_msg, bytes_length(ajp_req_attribute)...)
                ajp_msg = append(ajp_msg, ajp_req_attribute...)
                ajp_msg = append(ajp_msg, 0x00)
        }
        ajp_msg = append(ajp_msg, bytes_length(ajp_string)...)
        ajp_msg = append(ajp_msg, ajp_string...)
        ajp_msg = append(ajp_msg, 0x00)
        *ajp_msg_ptr = ajp_msg
}

func bytes_length(ajp_string string) []byte {
        ajp_string_len_buffer := new(bytes.Buffer)
        var ajp_string_len int16 = int16(len(ajp_string))
        binary.Write(ajp_string_len_buffer, binary.BigEndian, ajp_string_len)
        return ajp_string_len_buffer.Bytes()
}

func ajp_msg_append_int16(ajp_msg_ptr *[]byte, ajp_int16 int16) {
        ajp_msg := *ajp_msg_ptr
        ajp_int16_buffer := new(bytes.Buffer)
        binary.Write(ajp_int16_buffer, binary.BigEndian, ajp_int16)
        ajp_msg = append(ajp_msg, ajp_int16_buffer.Bytes()...)
        *ajp_msg_ptr = ajp_msg
}

func ajp_msg_append_int8(ajp_msg_ptr *[]byte, ajp_int8 int8) {
        ajp_msg := *ajp_msg_ptr
        ajp_int8_buffer := new(bytes.Buffer)
        binary.Write(ajp_int8_buffer, binary.BigEndian, ajp_int8)
        ajp_msg = append(ajp_msg, ajp_int8_buffer.Bytes()...)
        *ajp_msg_ptr = ajp_msg
}

func ajp_get_uint16(ajp_msg_ptr *[]byte, start uint16,end uint16) uint16 {
        ajp_msg := *ajp_msg_ptr
        return binary.BigEndian.Uint16(ajp_msg[start:start+end])
}

func ajp_get_string(ajp_msg_ptr *[]byte, start uint16, end uint16) string {
        ajp_msg := *ajp_msg_ptr
        return string(ajp_msg[start:start+end])
}

func ajp_return_string(ajp_msg_ptr *[]byte, start uint16) (string, uint16) {
        var ajp_string_end uint16
        var ajp_string_size uint16
        var ajp_string string
        ajp_msg := *ajp_msg_ptr
        ajp_string_size = ajp_get_uint16(&ajp_msg,start,2)
        //fmt.Printf("ajp_string_size :  %d\n", ajp_string_size)
        ajp_string = ajp_get_string(&ajp_msg,start+2,ajp_string_size)
        ajp_string_end = start + 2  + ajp_string_size + 1
        return ajp_string, ajp_string_end
}

func ajp_return_header(ajp_msg_ptr *[]byte, start uint16) (string,string, uint16) {
        sc_res_header_name := make(map[string]string)
        sc_res_header_name["\xA0\x01"]="Content-Type"
        sc_res_header_name["\xA0\x02"]="Content-Language"
        sc_res_header_name["\xA0\x03"]="Content-Length"
        sc_res_header_name["\xA0\x04"]="Date"
        sc_res_header_name["\xA0\x05"]="Last-Modified"
        sc_res_header_name["\xA0\x06"]="Location"
        sc_res_header_name["\xA0\x07"]="Set-Cookie"
        sc_res_header_name["\xA0\x08"]="Set-Cookie2"
        sc_res_header_name["\xA0\x09"]="Servlet-Engine"
        sc_res_header_name["\xA0\x0A"]="Status"
        sc_res_header_name["\xA0\x0B"]="WWW-Authenticate"
        var end uint16
        var ajp_header_name string
        var ajp_header_value string
        ajp_msg := *ajp_msg_ptr
        if strings.HasPrefix(ajp_get_string(&ajp_msg,start,1), "\xA0") {
                ajp_header_name=sc_res_header_name[ajp_get_string(&ajp_msg,start,2)]
                end = start + 2
        } else {
                ajp_header_name,end = ajp_return_string(&ajp_msg,start)
        }
        ajp_header_value,end = ajp_return_string(&ajp_msg,end)
        return ajp_header_name, ajp_header_value, end
}

func gzip_return_method(gzip_code string) (string) {
    gzip_compression_method := make(map[string]string)
    gzip_compression_method["\x00"]="store"
    gzip_compression_method["\x01"]="compress"
    gzip_compression_method["\x02"]="pack"
    gzip_compression_method["\x03"]="lzh"
    gzip_compression_method["\x04"]="reserved"
    gzip_compression_method["\x05"]="reserved"
    gzip_compression_method["\x06"]="reserved"
    gzip_compression_method["\x07"]="reserved"
    gzip_compression_method["\x08"]="deflate"
        gzip_method := gzip_compression_method[gzip_code]
    return gzip_method
}


func ajp_ping (conn net.TCPConn) {
        buffer := make([]byte, 8192)
        buffer[0] = 0x12
        buffer[1] = 0x34
        buffer[2] = 0x00
        buffer[3] = 0x01
        buffer[4] = 0x0A
        buffer = bytes.Trim(buffer, "\x00")
        _, err := conn.Write([]byte(buffer))
        if err != nil {
                println("Write failed:", err.Error())
                conn.Close()
                os.Exit(1)
        }

        reply := make([]byte, 1024)
        _, err = conn.Read(reply)
        if err != nil {
                println("Write to server failed:", err.Error())
                conn.Close()
                os.Exit(1)
        }

        /* Expected reply for a CPING */
        exp_reply := make([]byte, 1024)
        exp_reply[0] = 0x41
        exp_reply[1] = 0x42
        exp_reply[2] = 0x00
        exp_reply[3] = 0x01
        exp_reply[4] = 0x09
          //println("reply from server=", string(reply))
          //fmt.Printf("bytes read: [% x]\n", reply)
          //if (reply[0] == 0x41) && (reply[1] == 0x42) {
          //      println("ping OK=", string(reply))
          //}
          if bytes.Equal(reply, exp_reply) {
                  println("ping OK=", string(reply))
          }

}

type AjpResponsePacket struct {
        begin string
        length uint16
        status_code uint16
        status_message string
        prefix []byte
        message []byte
        num_headers uint16
        position uint16
        chunk_length uint16
        split bool
}

func (ajp_rp *AjpResponsePacket) browse() {
        ajp_rp.begin = ajp_get_string(&ajp_rp.message,0,2)
        ajp_rp.length = ajp_get_uint16(&ajp_rp.message,2,4)
        ajp_rp.prefix = ajp_rp.message[4:5]
}

func (ajp_rp *AjpResponsePacket) print_begin() {
        fmt.Printf("data begin : %s\n", ajp_rp.begin)
        fmt.Printf("data length : %d\n", ajp_rp.length)
        fmt.Printf("data type : %x\n", ajp_rp.prefix)
}

func (ajp_rp *AjpResponsePacket) headers() {
        var end uint16
        ajp_rp.status_code = ajp_get_uint16(&ajp_rp.message,5,7)
        ajp_rp.status_message,end = ajp_return_string(&ajp_rp.message,7)
        ajp_rp.position = end + 2
        ajp_rp.num_headers = ajp_get_uint16(&ajp_rp.message,end, end+2)
}

func (ajp_rp *AjpResponsePacket) chunk() {
        //var end uint16
        ajp_rp.chunk_length = ajp_get_uint16(&ajp_rp.message,5,7)
        ajp_rp.position = 7
}


func main() {
        flag.Parse()
        flag_url := flag.Arg(0)

        ajp_url, err := url.Parse(flag_url)
    if err != nil {
        panic(err)
    }

        host := ajp_url.Host
        AJPServerAddr, err := net.ResolveTCPAddr("tcp", host)
        if err != nil {
                panic(err)
        }
        conn, err := net.DialTCP("tcp", nil, AJPServerAddr)
        defer conn.Close()
        if err != nil {
                println("Dial failed:", err.Error())
                os.Exit(1)
        }
        //do an AJP ping
        //ajp_ping (*conn)
        client_ip,client_port, err := net.SplitHostPort(conn.LocalAddr().String())
        payload_buffer := make([]byte, 2, 8192)
        payload_buffer[0] = 0x02                                                          //0x02 = JK_AJP13_FORWARD_REQUEST
        payload_buffer[1] = 0x02                                                          //method = GET
        ajp_msg_append_string(&payload_buffer, "HTTP/1.1")                                //protocol
        ajp_msg_append_string(&payload_buffer, ajp_url.Path) //req_uri
        ajp_msg_append_string(&payload_buffer, client_ip)                            //remote_addr (client)
        ajp_msg_append_string(&payload_buffer, "")                                        //remote_host (client)
        ajp_msg_append_string(&payload_buffer, host)                //server_name (server)
        ajp_msg_append_int16(&payload_buffer, 80)                                         // port (integer)
        ajp_msg_append_int8(&payload_buffer, 0)                                           // is_ssl boolean
        ajp_msg_append_int16(&payload_buffer, 10)                                         // number of headers (integer)
        ajp_msg_append_sc_string(&payload_buffer, host, SC_REQ_HOST)
        ajp_msg_append_sc_string(&payload_buffer, "keep-alive", SC_REQ_CONNECTION)
        ajp_msg_append_sc_string(&payload_buffer, "no-cache", SC_REQ_PRAGMA)
        ajp_msg_append_sc_string(&payload_buffer, "no-cache", "Cache-Control1")
        ajp_msg_append_sc_string(&payload_buffer, "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", SC_REQ_ACCEPT)
        //ajp_msg_append_sc_string(&payload_buffer, "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36", SC_REQ_USER_AGENT)
        ajp_msg_append_sc_string(&payload_buffer, "AJPClient/0.1 (+https://github.com/hdanniel/ajpclient)", SC_REQ_USER_AGENT)
        ajp_msg_append_sc_string(&payload_buffer, "gzip,deflate,sdch", "Accept-Encoding")
        ajp_msg_append_sc_string(&payload_buffer, "en-EN,en;q=1", "Accept-Language")
        ajp_msg_append_sc_string(&payload_buffer, "", SC_REQ_COOKIE)
        //ajp_msg_append_sc_string(&payload_buffer, "\xCC", SC_REQ_CONTENT_LENGTH)
        ajp_msg_append_sc_string(&payload_buffer, "0", SC_REQ_CONTENT_LENGTH)
        ajp_msg_append_attribute_string(&payload_buffer, "", SC_A_JVM_ROUTE, "")
        ajp_msg_append_attribute_string(&payload_buffer, client_port, SC_A_REQ_ATTRIBUTE, "AJP_REMOTE_PORT")
        ajp_msg_append_attribute_string(&payload_buffer, "ACT", SC_A_REQ_ATTRIBUTE, "JK_LB_ACTIVATION")
        payload_buffer = append(payload_buffer, 0xFF) // request_terminator
        var payload_len int16 = int16(len(payload_buffer))

        /*fr_buffer is the first part of the packet we are going to send to the container
        Contents        0x12    0x34    Data Length (n)
        Data Length is only the data length of the payload
        */
        fr_buffer := make([]byte, 2, 8192)
        fr_buffer[0] = 0x12
        fr_buffer[1] = 0x34
        ajp_msg_append_int16(&fr_buffer, payload_len) // length of the payload in the forward request

        ajp_buffer := make([]byte, 2, 8192)
        ajp_buffer = append(fr_buffer, payload_buffer...)
        //fmt.Printf("bytes read: [% x]\n", ajp_buffer)

        _, err = conn.Write([]byte(ajp_buffer))
        if err != nil {
                println("Write failed:", err.Error())
                conn.Close()
                os.Exit(1)
        }

    var i uint16
    var n uint16
    var body_len int
        empty_buf := make([]byte, 2)
        empty_buf[0] = 0x00
        empty_buf[1] = 0x00
        ab_buf := make([]byte, 2)
        ab_buf[0] = 0x41
        ab_buf[1] = 0x42

        // for loop while there is content in the TCPConn
        for {
                //fmt.Printf("data : %x\n", ajp_reader.message)
                ajp_reader := new(AjpResponsePacket)
                ajp_reader.message = make([]byte, 16384)
                conn.SetReadDeadline(time.Now().Add(10 * time.Second))
                _, err = conn.Read(ajp_reader.message)

                if err != nil {
                        //fmt.Printf("%s\n", err.Error())
                        if strings.HasSuffix(err.Error(), "i/o timeout") {
                                println("Connection idle after 10 seconds")
                        } else {
                                println("Read from server failed:", err.Error())
                        }
                        conn.Close()
                        os.Exit(1)
                }
                // for loop white there is content in the Reader
                LoopContent:
                for {
                        // if message is empty, break the loop
                        if (bytes.Equal(ajp_reader.message,nil)) {
                                break
                        }
                        // if message don't begin with AB we need to check
                        if !(bytes.Equal(ajp_reader.message[0:2], ab_buf)) {
                                // if message starts with 0000 probably is garbage
                                if bytes.Equal(ajp_reader.message[0:2], empty_buf) {
                                        break
                                // else probably is text
                                } else {
                                        ab_index := bytes.Index(ajp_reader.message,ab_buf)
                                        if ab_index == -1 {
                                                break
                                        } else {
                                                ab_position := uint16(ab_index)
                                                ajp_reader.position = ab_position
                                                ajp_reader.message = ajp_reader.message[ajp_reader.position:]
                                        }
                                }
                        }
                        ajp_reader.browse()
                        //ajp_reader.print_begin()
                                        //fmt.Printf("%d\n", len(ajp_reader.message))
                        switch int(ajp_reader.prefix[0]) {
                                case AJP13_SEND_BODY_CHUNK:
                                        ajp_reader.chunk()
                                        //fmt.Printf("chunk length : %d\n", ajp_reader.chunk_length)
                                        gzip_buf := make([]byte, 2)
                                        gzip_buf[0] = 0x1F
                                        gzip_buf[1] = 0x8B
                                        //fmt.Printf("reader pos : %d\n", ajp_reader.position)
                                        if bytes.Equal(ajp_reader.message[7:9], gzip_buf) {
                                                fmt.Printf("gzip compression method: %s\n", gzip_return_method(ajp_get_string(&ajp_reader.message,9,1)))
                                                fmt.Printf("gzip flags: %x\n", ajp_reader.message[10])
                                                fmt.Printf("gzip modification time: %x\n", ajp_reader.message[11:15])
                                                fmt.Printf("gzip extra flags: %x\n", ajp_reader.message[15])
                                                fmt.Printf("gzip OS type: %x\n", ajp_reader.message[16])
                                                ajp_body_buf := bytes.NewBuffer(ajp_reader.message[17:17+ajp_reader.chunk_length])
                                                ajp_body_reader := flate.NewReader(ajp_body_buf)
                                                io.Copy(os.Stdout, ajp_body_reader)
                                                ajp_reader.position = 17 + ajp_reader.chunk_length
                                        } else {
                                                //fmt.Printf("slice len : %d\n", len(ajp_reader.message))
                                                ajp_message_length := uint16(len(ajp_reader.message))
                                                if  ajp_reader.chunk_length < ajp_message_length {
                                                        fmt.Printf("%s\n", ajp_get_string(&ajp_reader.message,7,ajp_reader.chunk_length))
                                                        ajp_reader.position = 7 + ajp_reader.chunk_length + 1
                                                } else {
                                                        fmt.Printf("%s\n", ajp_get_string(&ajp_reader.message,7,ajp_message_length-7))
                                                        break LoopContent
                                                }
                                        }
                                        ajp_reader.message = ajp_reader.message[ajp_reader.position:]
                                case AJP13_SEND_HEADERS:
                                        var header_name,header_value string
                                        ajp_reader.headers()
                                        fmt.Printf("Status Code: %d %s\n",ajp_reader.status_code,ajp_reader.status_message)
                                        //fmt.Printf("http_status_msg : %s\n" ,ajp_reader.status_message)
                                        //fmt.Printf("num_headers: %d\n", ajp_reader.num_headers)
                                        i = ajp_reader.position
                                        for n = 0; n < ajp_reader.num_headers; n++ {
                                                header_name, header_value, i = ajp_return_header(&ajp_reader.message,i)
                                                fmt.Printf("> %s: %s \n", header_name,header_value)
                                                if header_name == "Content-Length" {
                                                        body_len,_ = strconv.Atoi(header_value)
                                                        body_len += 4
                                                }
                                        }
                                        ajp_reader.position = i
                                        ajp_reader.message = ajp_reader.message[ajp_reader.position:]
                                case AJP13_END_RESPONSE:
                                        //fmt.Printf("reuse: %x\n", ajp_reader.message[5])
                                        if ajp_reader.message[5]==0x01  {
                                                ajp_reader.message = ajp_reader.message[5:]
                                                conn.Close()
                                                os.Exit(1)
                                        } else {
                                                conn.Close()
                                                os.Exit(1)
                                        }
                                default:
                                        break
                        }
                } //end for message
        } // end for conn
}

package main

import (
        "bytes"
        "encoding/binary"
        "fmt"
        "net"
        "os"
        "strings"
        "flag"
        //"reflect"
        //"strconv"
        //"encoding/hex"
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
}

func (ajp_rp *AjpResponsePacket) browse() {
        ajp_rp.begin = ajp_get_string(&ajp_rp.message,0,2)
        ajp_rp.length = ajp_get_uint16(&ajp_rp.message,2,4)
        ajp_rp.prefix = ajp_rp.message[4:5]
}

func (ajp_rp *AjpResponsePacket) headers() {
        var end uint16
        ajp_rp.status_code = ajp_get_uint16(&ajp_rp.message,5,7)
        ajp_rp.status_message,end = ajp_return_string(&ajp_rp.message,7)
        ajp_rp.position = end + 2
        ajp_rp.num_headers = ajp_get_uint16(&ajp_rp.message,end, end+2)
}

func main() {
        flag.Parse()
        host := flag.Arg(0)
        host += ":8009"
        println(host)
        AJPServerAddr, err := net.ResolveTCPAddr("tcp", host)
        conn, err := net.DialTCP("tcp", nil, AJPServerAddr)
        if err != nil {
                println("Dial failed:", err.Error())
                os.Exit(1)
        }
        ajp_ping (*conn)

        payload_buffer := make([]byte, 2, 8192)
        payload_buffer[0] = 0x02                                                          //0x02 = JK_AJP13_FORWARD_REQUEST
        payload_buffer[1] = 0x02                                                          //method = GET
        ajp_msg_append_string(&payload_buffer, "HTTP/1.1")                                //protocol
        //ajp_msg_append_string(&payload_buffer, "/axcessfinancial-connection-client-hpaz") //req_uri
        ajp_msg_append_string(&payload_buffer, "/") //req_uri
        ajp_msg_append_string(&payload_buffer, "10.65.31.246")                            //remote_addr (client)
        ajp_msg_append_string(&payload_buffer, "")                                        //remote_host (client)
        //ajp_msg_append_string(&payload_buffer, "locpdev.cngfinancial.com")                //server_name (server)
        ajp_msg_append_string(&payload_buffer, "10.65.31.180")                //server_name (server)
        ajp_msg_append_int16(&payload_buffer, 80)                                         // port (integer)
        ajp_msg_append_int8(&payload_buffer, 0)                                           // is_ssl boolean
        ajp_msg_append_int16(&payload_buffer, 10)                                         // number of headers (integer)
        //ajp_msg_append_sc_string(&payload_buffer, "locpdev.cngfinancial.com", SC_REQ_HOST)
        ajp_msg_append_sc_string(&payload_buffer, "10.65.31.180", SC_REQ_HOST)
        ajp_msg_append_sc_string(&payload_buffer, "keep-alive", SC_REQ_CONNECTION)
        ajp_msg_append_sc_string(&payload_buffer, "no-cache", SC_REQ_PRAGMA)
        ajp_msg_append_sc_string(&payload_buffer, "no-cache", "Cache-Control1")
        ajp_msg_append_sc_string(&payload_buffer, "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", SC_REQ_ACCEPT)
        ajp_msg_append_sc_string(&payload_buffer, "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36", SC_REQ_USER_AGENT)
        ajp_msg_append_sc_string(&payload_buffer, "gzip,deflate,sdch", "Accept-Encoding")
        ajp_msg_append_sc_string(&payload_buffer, "es-ES,es;q=0.8,en;q=0.6", "Accept-Language")
        ajp_msg_append_sc_string(&payload_buffer, "optimizelyEndUserId=oeu1408650368327r0.16359442425891757; COMPANY_ID=10132; ID=336b55396f6845306655513d; PASSWORD=6f656c6959754d4752484a6d5a726455546c4c2b7a413d3d; REMEMBER_ME=true; LOGIN=6870617a; SCREEN_NAME=4756327a36384778736c303d; optimizelySegments=%7B%22175595738%22%3A%22none%22%2C%22175595|366.5|109|136|135.5|137|371|331.5|328.5|334.5; COOKIE_SUPPORT=true; JSESSIONID=9D96A74D66EE753A5A63ABAD0E12C42E; GUEST_LANGUAGE_ID=en_US", SC_REQ_COOKIE)
        //ajp_msg_append_sc_string(&payload_buffer, "\xCC", SC_REQ_CONTENT_LENGTH)
        ajp_msg_append_sc_string(&payload_buffer, "0", SC_REQ_CONTENT_LENGTH)
        ajp_msg_append_attribute_string(&payload_buffer, "cfi_node_79", SC_A_JVM_ROUTE, "")
        ajp_msg_append_attribute_string(&payload_buffer, "20549", SC_A_REQ_ATTRIBUTE, "AJP_REMOTE_PORT")
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
        ajp_headers := new(AjpResponsePacket)
        ajp_headers.message = make([]byte, 16384)
        _, err = conn.Read(ajp_headers.message)
        if err != nil {
                println("Write to server failed:", err.Error())
                conn.Close()
                os.Exit(1)
        }
        ajp_headers.browse()
        fmt.Printf("data begin : %s\n", ajp_headers.begin)
        fmt.Printf("data length : %d\n", ajp_headers.length)
        fmt.Printf("data type : %x\n", ajp_headers.prefix)

        var i uint16
        var n uint16
        var header_name,header_value string
        if ajp_headers.prefix[0] == 4 {
                ajp_headers.headers()
                fmt.Printf("http_status_code: %d\n",ajp_headers.status_code)
                fmt.Printf("http_status_msg : %s\n" ,ajp_headers.status_message)
                fmt.Printf("num_headers: %d\n", ajp_headers.num_headers)
                i = ajp_headers.position
                for n = 0; n < ajp_headers.num_headers; n++ {
                        header_name, header_value, i = ajp_return_header(&ajp_headers.message,i)
                        fmt.Printf("> %s: %s \n", header_name,header_value)
                }
        }
        ajp_body := new(AjpResponsePacket)
        ajp_body.message = make([]byte, 16384)
        _, err = conn.Read(ajp_body.message)
        ajp_body.browse()
        fmt.Printf("data begin : %s\n", ajp_body.begin)
        fmt.Printf("data length : %d\n", ajp_body.length)
        fmt.Printf("data type : %x\n", ajp_body.prefix)

        conn.Close()
}

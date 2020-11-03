#
# myintcl - a pure-Tcl implementation of MySQL interface
#
# For information on usage and redistribution, and for a DISCLAIMER OF ALL
# WARRANTIES, see the file "LICENSE.md" in this distribution.  
#

namespace eval myintcl {
    variable sock

    namespace eval mysqlcmd {
        variable QUIT 1
        variable QUERY 3
        variable CHANGE_USER 17
    }
    namespace eval strbuf {
        variable strbuf
        variable p
        variable nextid 0
        proc create {str} {
            variable strbuf; variable p; variable nextid
            set id $nextid
            set strbuf($id) $str
            set p($id) 0
            incr nextid
            return $id
        }
        proc eat {id length} {
            variable strbuf; variable p
            set ret [string range $strbuf($id) $p($id) [expr $p($id) + $length - 1]]
            incr p($id) $length
            return $ret
        }
        proc eatint8 {id} {
            variable strbuf; variable p
            set ret [string range $strbuf($id) $p($id) $p($id)]
            binary scan $ret c ret
            incr p($id)
            return $ret
        }
        proc eatint16 {id} {
            variable strbuf; variable p
            set ret [string range $strbuf($id) $p($id) [expr $p($id) + 1]]
            binary scan $ret s ret
            incr p($id) 2
            return $ret
        }
        proc eatuntilnull {id} {
            variable strbuf; variable p
            set ret ""
            while {[set i [eat $id 1]] != "\0" && $p($id) <= [string length $strbuf($id)]} {
                append ret $i
            }
            return $ret
        }
    }
    namespace eval packet {
        variable packetnum
        variable dump 0

        proc toprintable {str} {
            set ret ""
            for {set i 0} {$i < [string length $str]} {incr i} {
                set ch [string range $str $i $i]
                if {![string is ascii $ch] || ![string is print $ch]} {
                    binary scan $ch H2 ch
                    set ch "\\x$ch"
                }
                append ret $ch
            }
            return $ret
        }

        proc dump {v length num packet} {
            puts "$v"
            puts "packet length: $length"
            puts "packet num: $num"
            puts "packet : [toprintable $packet]"
            puts ""
        }

        proc receivepacket {sock} {
            variable packetnum
            variable length
            binary scan [read $sock 3]\0 i length
            binary scan  [read $sock 1] c packetnum($sock)
            set packet [read $sock $length]

            dump "packet received" $length $packetnum($sock) $packet

            return $packet
        }
        proc getpacketnum {sock} {
            variable packetnum
            return $packetnum($sock)
        }
        proc sendpacket {sock packet num} {
            variable packetnum
            set length [string length $packet]
            puts -nonewline $sock [string range [binary format i $length] 0 2]
            puts -nonewline $sock [binary format c $num]
            puts -nonewline $sock $packet
            flush $sock

            dump "packet sent" $length $num $packet

        }
    }

    proc receivegreeting {sock} {
        array set ret {}

        set packet [strbuf::create [packet::receivepacket $sock]]

        binary scan [strbuf::eat $packet 1] c ret(protocol_ver)
        set ret(mysql_ver) [strbuf::eatuntilnull $packet]
        binary scan [strbuf::eat $packet 4] i ret(thread_id)
        set ret(salt) [strbuf::eatuntilnull $packet]
        binary scan [strbuf::eat $packet 2] c ret(caps)
        binary scan [strbuf::eat $packet 1] c ret(charset)
        binary scan [strbuf::eat $packet 1] c ret(status)

        return [array get ret]
    }

    proc sendauthinfo {sock username password database} {
        set responsecode {}

        set packet {}
        append packet "\x8d\x00"; # caps
        append packet "\x00\x00\x00"; # maxpacket
        append packet "$username\0"; # username
        append packet "$password\0"; # encrypted password
        append packet "$database"; # database

        packet::sendpacket $sock $packet [expr [packet::getpacketnum $sock] + 1]

        set packet [strbuf::create [packet::receivepacket $sock]]
        binary scan [strbuf::eat $packet 1] c responsecode

        return $responsecode
    }

    proc sendquery {sock statement} {
        set packet {}
        append packet [binary format c $mysqlcmd::QUERY]
        append packet $statement

        packet::sendpacket $sock $packet 0
    }

    proc sendquit {sock} {
        packet::sendpacket $sock [binary format c $mysqlcmd::QUIT] 0
    }

    proc connect {args} {
        variable sock

        set host localhost
        set username ""
        set password ""
        set database ""
        set port 3306

        if {[llength $args] >= 6} {
            set port [lindex $args 5]
        }
        if {[llength $args] >= 5} {
            set database [lindex $args 4]
        }
        if {[llength $args] >= 4} {
            set password [lindex $args 3]
        }
        if {[llength $args] >= 3} {
            set user [lindex $args 2]
        }
        if {[llength $args] >= 2} {
            set host [lindex $args 1]
        }
        set handle [lindex $args 0]

        set sock($handle) [socket $host $port]
        fconfigure $sock($handle) -translation binary
        receivegreeting $sock($handle)
        return [sendauthinfo $sock($handle) $username $password $database]
    }
    proc disconnect {handle} {
        variable sock
        sendquit $sock($handle)
    }
    proc query {handle statement} {
        variable sock
        variable responsecode

        sendquery $sock($handle) $statement

        set packet [strbuf::create [packet::receivepacket $sock($handle)]]
        set numcolumn [strbuf::eatint8 $packet]

        if {$numcolumn == -1} {
            set errcode [strbuf::eatint16 $packet]
            set errmsg [strbuf::eatuntilnull $packet]
            error $errmsg $errmsg [list MYSQL $errcode]
        }
        if {$numcolumn == 0} {
            set recordsaffected [strbuf::eatint8 $packet]
            set id [strbuf::eatint8 $packet]
            return
        }
        while {[set packet [packet::receivepacket $sock($handle)]] != "\xfe"} {
            set packet [strbuf::create $packet]
            set length [strbuf::eatint8 $packet]
            set tablename [strbuf::eat $packet $length]
            puts "tablename: $tablename"
            set length [strbuf::eatint8 $packet]
            set columnname [strbuf::eat $packet $length]
            puts "columnname: $columnname"
        }

        set result [list]
        while {[set packet [packet::receivepacket $sock($handle)]] != "\xfe"} {
            set packet [strbuf::create $packet]
            set row [list]
            for {set i 0} {$i < $numcolumn} {incr i} {
                set length [strbuf::eatint8 $packet]
                set record [strbuf::eat $packet $length]
                lappend row $record
                puts "record: $record"
            }
            lappend result $row
        }
        return $result
    }
    proc sql {args} {eval [concat do sql $args]}
    proc sql1 {args} {eval [concat do sql1 $args]}
    proc sql2 {args} {eval [concat do sql2 $args]}
    proc sql3 {args} {eval [concat do sql3 $args]}
    proc sql4 {args} {eval [concat do sql4 $args]}
    proc sql5 {args} {eval [concat do sql5 $args]}
    proc do {handle command args} {
        switch $command {
            connect {eval [concat connect $handle $args]}
            disconnect {eval [concat disconnect $handle $args]}
            query {eval [concat query $handle $args]}
            default {query $handle [concat $command $args]}
        }
    }
    namespace export sql*
}

namespace import myintcl::sql*

sql connect localhost "" "" test

while {1} {
    puts -nonewline "> "
    flush stdout
    set input [gets stdin]
    if {$input == "exit"} break
    if {[catch {sql query $input} result]} {
        puts $errorCode:$result
    } else {
        puts $result
    }
}

sql disconnect

exit

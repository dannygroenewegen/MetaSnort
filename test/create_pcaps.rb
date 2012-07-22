#!/usr/bin/env ruby

$:.unshift(File.join('','opt','framework-3.6.0','msf3','lib'))

require 'rex'
require 'msf/base'
require 'socket'

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create(
    :module_types => [ Msf::MODULE_PAYLOAD, Msf::MODULE_ENCODER, Msf::MODULE_NOP ],
    'DisableDatabase' => true
)

# read payload options file
payload_opts = Hash[File.read('payload_options.cfg').scan(/(.+?):(.+)/)]

puts payload_opts

# Start a local tcpserver to send payloads to
puts "Starting tcp server"
tcp_server = TCPServer.new('127.0.0.2',4444)

# iterate all payloads
$framework.payloads.each_module { |name, mod|
    
    puts "Generating "+ name
    
    begin
        # generate payload four times with different option sets
        payload = $framework.payloads.create(name)
        s1 = payload.generate_simple(
            'Format'    => 'raw',
            'Options'   => payload_opts,
            'Encoder'   => nil)
    rescue
        $stderr.puts "Error generating #{name}: #{$!}"
        puts "#{$!.backtrace}"
    end
    
    puts "Start tcpdump capture..."
    system('tcpdump -i lo -n -w ./captures/'+name.gsub(/\//,'-')+'.pcap&')
    sleep 1
    puts "Sending the payload..."
    
    # send the payload to a tcp socket
    t = TCPsocket.new('127.0.0.2','4444','127.0.0.1')
    t.write(s1)
    t.close
    
    sleep 2
    puts 'Saving tcpdump capture...\n'
    system('killall tcpdump')
    sleep 1
}

puts "Done"

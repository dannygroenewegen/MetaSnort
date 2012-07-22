#!/usr/bin/env ruby

# iterate all payloads

total = 0
total_detected = 0

$alertsfile = './snort/logs/alert'

Dir.glob('./captures/*.pcap').each { |file|
    puts "Parsing "+file 
    
    puts "Starting Snort..."
    system('snort -A fast -c ./snort/snort.conf -K none -k none -q -l ./snort/logs/ -r '+file)
    sleep 0.5
    
    detected = false
    # read snort log file
    if File.exists?($alertsfile)
        puts "Snort detected:"
        alerts = File.new($alertsfile,'r')
        while (line = alerts.gets)
            detected = true
            puts line
        end
        alerts.close
        File.delete($alertsfile)
    else
        puts "Snort detected nothing"
    end
    
    total = total + 1
    if detected
        total_detected = total_detected + 1
    end
}

puts "Total:"+total.to_s
puts "Detected:"+total_detected.to_s

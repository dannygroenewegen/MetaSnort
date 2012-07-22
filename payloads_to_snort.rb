#!/usr/bin/env ruby

$:.unshift(File.join('','opt','framework-3.6.0','msf3','lib'))

require 'rex'
require 'msf/base'

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create(
    :module_types => [ Msf::MODULE_PAYLOAD, Msf::MODULE_ENCODER, Msf::MODULE_NOP ],
    'DisableDatabase' => true
)

$sid = 1000000

# read payload options file
payload_opts = Hash[File.read('payload_options.cfg').scan(/(.+?):(.+)/)]
payload_opts_diff = {}
# split up the diff options
payload_opts.each{ |x|
    a,b = x[1].split(",")
    payload_opts[x[0]] = a
    payload_opts_diff[x[0]] = b
}

def lcs_size(s1, s2)
   num=Array.new(s1.size){Array.new(s2.size)}
   len,posi,posj=0

   s1.scan(/./).each_with_index do |l1,i |
     s2.scan(/./).each_with_index do |l2,j |

        unless l1==l2
           num[i][j]=0
        else
          (i==0 || j==0)? num[i][j]=1 : num[i][j]=1 + num[i-1][j-1]
          if num[i][j] > len
            len = ans = num[i][j]
            posi = i
            posj = j
          end
        end
     end
   end
   [len,posi,posj]
end

#regexp filter for hex output
#require a minimum of two two character hex blocks seperated by whitespace
$regexpfilter = Regexp.new(/(\S{2}\s){3,}\S{2}/)

def common_payload(s1,s2)
    
    lcs = lcs_size(s1,s2)
    
    #string from size and position
    #filter using regexp
    if lcs[0] == 0
        return []
    else
        lcs_s = s1[lcs[1]-lcs[0]+1..lcs[1]]
        lcs_s = lcs_s[$regexpfilter]
        if lcs_s.nil? || lcs_s.empty?
            return []
        end
    end

    # recursive left
    if (lcs[1]-lcs[0] < 0) || (lcs[2]-lcs[0] < 0)
        lcsleft = []
    else
        lcsleft = common_payload(
            s1[0..(lcs[1]-lcs[0])],
            s2[0..(lcs[2]-lcs[0])])
    end
    #recursive right
    if (lcs[1] >= s1.length ) || (lcs[2] >= s2.length)
        lcsright = []
    else
        lcsright = common_payload(
            s1[(lcs[1]+1)..s1.length],
            s2[(lcs[2]+1)..s2.length])
    end

    return lcsleft.push(lcs_s).push(lcsright)
end

# writes out the signatures to the snort rules file
def write_rule(name,content)
    puts "Writing rule..."
    
    $out.write('alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"'+name+'"; flow:established; ')
    
#    ERROR: ./snort/./rules/metasploit_payloads.rules(107) Line greater than or equal to 32768 characters which is more than the parser is willing to handle.  Try splitting it up on multiple lines if possible.

    
    content.each { |x|
        if x.to_s.length >= 5
            $out.write('content:"| '+x.strip+' |"; ')
        end
    }
    $out.write("sid:#{$sid}; rev:1;)\n")
    $sid = $sid + 1
end

#compare two strings for similar parts
# taking into account a maximum blocksize to speed things up
def compare_two(s1,s2)
    contents = []
    block_size = 1000
    pos = 0
    
    #find static parts using block_size splits
    while pos < s1.length
        #check if a full block is possible
        if pos+block_size <= s1.length
            contents.push(common_payload(s1[pos..(pos+block_size-1)], s2[pos..(pos+block_size-1)]))
            pos = pos+block_size
        else
            contents.push(common_payload(s1[pos..(s1.length-1)],s2[pos..(s2.length-1)]))
            pos = s1.length
        end
    end
    
    return contents.flatten
end

# open output file
$out = File.open('metasploit_payloads.rules', 'w')

# iterate all payloads
$framework.payloads.each_module { |name, mod|
    payload_name = "#{name}"
    puts "Generating "+ payload_name    
    
    begin
        # generate payload four times with different option sets
        payload = $framework.payloads.create(payload_name)
        s1 = payload.generate_simple(
            'Format'    => 'raw',
            'Options'   => payload_opts,
            'Encoder'   => nil)
        payload = $framework.payloads.create(payload_name)
        s2 = payload.generate_simple(
            'Format'    => 'raw',
            'Options'   => payload_opts_diff,
            'Encoder'   => nil)
        payload = $framework.payloads.create(payload_name)
        s3 = payload.generate_simple(
            'Format'    => 'raw',
            'Options'   => payload_opts_diff,
            'Encoder'   => nil)
        payload = $framework.payloads.create(payload_name)
        s4 = payload.generate_simple(
            'Format'    => 'raw',
            'Options'   => payload_opts,
            'Encoder'   => nil)
        
        puts "Converting payloads to hex format..."
        s1 = Rex::Text.to_hex(s1,' ').to_s
        s2 = Rex::Text.to_hex(s2,' ').to_s
        s3 = Rex::Text.to_hex(s3,' ').to_s
        s4 = Rex::Text.to_hex(s4,' ').to_s
        puts "Extracting static payload parts..."
        
        #extract the static parts from 4 generated payloads
        contents1 = compare_two(s1,s2)
        contents2 = compare_two(s3,s4)
        contents = compare_two(contents1.join(' xx '),contents2.join(' yy '))
        
        # check if static parts are found
        if contents.length > 0
            #write out the rule from static content parts
            write_rule(payload_name,contents)
        else
            puts "No static parts found, skipping"
        end
        
    rescue
        $stderr.puts payload_name
        $stderr.puts "Error generating payload: #{$!}"
        puts "#{$!.backtrace}"
    end
}

$out.close

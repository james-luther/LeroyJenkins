#!/usr/bin/env python

import subprocess, pygtk, gtk, os, gobject 
import pycurl, cStringIO, re, cmd, optparse

nodes = ['Nodes']
server = None
auth = None
cnode = None
cnodes = []
connected = False
authenticated = False

class Gui:

    def __init__(self):
        self.builder = gtk.Builder()
        self.builder.add_from_file(os.path.dirname(__file__) + '/leroy-jenkins.glade')
        self.textview = self.builder.get_object('textview1')
        self.window = self.builder.get_object('main_window')
        self.textview.modify_base(gtk.STATE_NORMAL,gtk.gdk.color_parse('#000000'))
        self.textview.modify_text(gtk.STATE_NORMAL,gtk.gdk.color_parse('#FFFFFF'))
        self.nodes = self.builder.get_object('nodesbox')
        node_store = gtk.ListStore(str)
        for node in nodes:
            node_store.append(nodes)
        self.nodes.set_active(0)
        cell = gtk.CellRendererText()
        self.nodes.set_model(node_store)
        self.nodes.pack_start(cell, False)
        self.nodes.add_attribute(cell, 'text', 0)
        if self.window:
            self.window.connect("destroy", gtk.main_quit)
        handlers = {
                    "command_sent"  :   self.command_sent,
                    "destroy"       :   gtk.main_quit,
                    "connect"       :   self.connect,
        }
        self.builder.connect_signals(handlers)

    def connect(self, widget):
        global nodes
        buf = cStringIO.StringIO()
        self.server = self.builder.get_object('entry1').get_text()
        self.port = self.builder.get_object('entry2').get_text()
        self.auth = self.builder.get_object('auth_check').get_active()
        self.password = self.builder.get_object('entry3').get_text()
        self.user = self.builder.get_object('entry4').get_text()
        user_auth = self.user + ':' + self.password
        self.nodes = self.builder.get_object('nodesbox')
        c = pycurl.Curl()
        c.setopt(c.URL, self.server + ':' + self.port + '/scriptText')
        if self.auth is True:
            c.setopt(c.USERPWD, user_auth)
        c.setopt(c.POSTFIELDS, "script=for (aSlave in hudson.model.Hudson.instance.slaves) {"\
                               "println(aSlave.name);}")
        c.setopt(c.WRITEFUNCTION, buf.write)
        try:
            c.perform()
        except pycurl.error, e:
            errno, errstr = e
            self.textview = self.builder.get_object('textview1')
            self.textview.get_buffer().insert_at_cursor(errstr + '\n')
            self.textview.scroll_mark_onscreen(self.textview.get_buffer().get_insert())
            return False

        if buf.getvalue().split('\n') == nodes:
            return False
        else:
            nodes = buf.getvalue().split('\n')
            self.nodes.clear()
            node_store = gtk.ListStore(str)
            cell = gtk.CellRendererText()
            self.nodes.set_model(node_store)
            self.nodes.pack_start(cell, False)
            self.nodes.add_attribute(cell, 'text', 0)
            self.nodes.append_text('Nodes')
            self.nodes.set_active(0)
            for node in nodes:
                self.nodes.append_text(node)


    def command_sent(self, widget):
        buf = cStringIO.StringIO()
        self.server = self.builder.get_object('entry1').get_text()
        self.port = self.builder.get_object('entry2').get_text()
        self.auth = self.builder.get_object('auth_check').get_active()
        self.command = self.builder.get_object('command_entry')
        self.local = self.builder.get_object('local_button')
        self.remote = self.builder.get_object('remote_button')
        self.node = self.builder.get_object('node_button')
        self.nodes = self.builder.get_object('nodesbox')
        status_local = self.local.get_active()
        status_remote = self.remote.get_active()
        status_node = self.node.get_active()
        index = self.nodes.get_active()
        model = self.nodes.get_model()
        item = nodes[index - 1]
        if status_local is True:
            proc = subprocess.Popen(self.command.get_text(), shell=True, stdout=subprocess.PIPE)
            gobject.io_add_watch(proc.stdout,
                                gobject.IO_IN,
                                self.write_output)
            self.command.set_text('')
        if status_remote is True:
            if self.auth is True:
                self.password = self.builder.get_object('entry3').get_text()
                self.user = self.builder.get_object('entry4').get_text()
                user_auth = self.user + ':' + self.password
                c = pycurl.Curl()
                c.setopt(c.URL, self.server + ':' + self.port + '/scriptText')
                c.setopt(c.USERPWD, user_auth)
                c.setopt(c.POSTFIELDS, 'script=println "' + self.command.get_text() + '".execute().text')
                c.setopt(c.WRITEFUNCTION, buf.write)
                try:
                    c.perform()
                    self.textview = self.builder.get_object('textview1')
                    self.textview.get_buffer().insert_at_cursor(buf.getvalue())
                    self.textview.scroll_mark_onscreen(self.textview.get_buffer().get_insert())
                    self.command.set_text('')
                except pycurl.error, e:
                    errno, errstr = e
                    self.textview.get_buffer().insert_at_cursor(errstr + '\n')
                    self.textview.scroll_mark_onscreen(self.textview.get_buffer().get_insert())
                    self.command.set_text('')
            else:
                c = pycurl.Curl()
                c.setopt(c.URL, self.server + ':' + self.port + '/scriptText')
                c.setopt(c.POSTFIELDS, 'script=println "' + self.command.get_text() + '".execute().text')
                c.setopt(c.WRITEFUNCTION, buf.write)
                try:
                    c.perform()
                    self.textview = self.builder.get_object('textview1')
                    self.textview.get_buffer().insert_at_cursor(buf.getvalue())
                    self.textview.scroll_mark_onscreen(self.textview.get_buffer().get_insert())
                    self.command.set_text('')
                except pycurl.error, e:
                    errno, errstr = e
                    self.textview = self.builder.get_object('textview1')
                    self.textview.get_buffer().insert_at_cursor(errstr + '\n')
                    self.textview.scroll_mark_onscreen(self.textview.get_buffer().get_insert())
                    self.command.set_text('')
        if status_node is True:
            if self.auth is True:
                self.password = self.builder.get_object('entry3').get_text()
                self.user = self.builder.get_object('entry4').get_text()
                user_auth = self.user + ':' + self.password
                c = pycurl.Curl()
                c.setopt(c.URL, self.server + ':' + self.port + '/computer/' + str(item) + '/scriptText')
                c.setopt(c.USERPWD, user_auth)
                c.setopt(c.POSTFIELDS, 'script=println "' + self.command.get_text() + '".execute().text')
                c.setopt(c.WRITEFUNCTION, buf.write)
                try:
                    c.perform()
                    self.textview = self.builder.get_object('textview1')
                    self.textview.get_buffer().insert_at_cursor(buf.getvalue())
                    self.textview.scroll_mark_onscreen(self.textview.get_buffer().get_insert())
                    self.command.set_text('')
                except pycurl.error, e:
                    errno, errstr = e
                    self.textview.get_buffer().insert_at_cursor(errstr + '\n')
                    self.textview.scroll_mark_onscreen(self.textview.get_buffer().get_insert())
                    self.command.set_text('')
            else:
                c = pycurl.Curl()
                c.setopt(c.URL, self.server + ':' + self.port + '/computer/' + str(item) + '/scriptText')
                c.setopt(c.POSTFIELDS, 'script=println "' + self.command.get_text() + '".execute().text')
                c.setopt(c.WRITEFUNCTION, buf.write)
                try:
                    c.perform()
                    self.textview = self.builder.get_object('textview1')
                    self.textview.get_buffer().insert_at_cursor(buf.getvalue())
                    self.textview.scroll_mark_onscreen(self.textview.get_buffer().get_insert())
                    self.command.set_text('')
                except pycurl.error, e:
                    errno, errstr = e
                    self.textview.get_buffer().insert_at_cursor(errstr + '\n')
                    self.textview.scroll_mark_onscreen(self.textview.get_buffer().get_insert())
                    self.command.set_text('')
 
    def write_output(self, fd, condition):
        if condition == gobject.IO_IN:
            char = fd.read(1)
            self.textview = self.builder.get_object('textview1')
            self.textview.get_buffer().insert_at_cursor(char)
            self.textview.scroll_mark_onscreen(self.textview.get_buffer().get_insert())
            return True
        else:
            return False


class CommandShell(cmd.Cmd, object):

    
    def do_connect(self, line):
        global server
        global auth
        global connected
        global authenticated
        server = raw_input('Jenkins Server URL: (ex: http://jenkins:8080) ')
        a = raw_input('Use authentication? (y/n):')
        if a is 'y':
            auth = raw_input('Username:Password: ')
            c = pycurl.Curl()
            c.setopt(c.URL, server + '/scriptText')
            c.setopt(c.USERPWD, auth)
            c.setopt(c.POSTFIELDS, "script=println 'cat /dev/null'.execute().text")
            try:
                output = str(c.perform())
                if output is not None:
                    connected = True
                    authenticated = True
                    print '[+] Connected to ' + server
                else:
                    print '[!] Unable to connect to ' + server
            except pycurl.error, e:
                errno, errstr = e
                print '[!] Error ' + errstr
                return False
        elif a is 'n':
            c = pycurl.Curl()
            c.setopt(c.URL, server + '/scriptText')
            c.setopt(c.POSTFIELDS, "script=println 'cat /dev/null'.execute().text")
            try:
                output = str(c.perform())
                if output is not None:
                    connected = True
                    print '[+] Connected to ' + server
                else:
                    print '[!] Unable to connect to ' + server
            except pycurl.error, e:
                errno, errstr = e
                print '[!] Error ' + errstr
                return False


    def help_connect(self):
        print '\nConnect to a Jenkins Server. All server information will '\
                'be asked for once this command is run.\n'
    
    
    def do_clear(self, line):
        os.system('clear')


    def help_clear(self):
        print "\nClear the current screen\n"

    
    def do_nodes(self, line):
        global cnodes
        buf = cStringIO.StringIO()
        if connected is not True:
            print '[!] You must connect to server first!'
        else:
            if authenticated is True:
                c = pycurl.Curl()
                c.setopt(c.URL, server + '/scriptText')
                c.setopt(c.USERPWD, auth)
                c.setopt(c.POSTFIELDS, "script=for (aSlave in hudson.model.Hudson.instance.slaves) {"\
                                        "println('====================');"\
                                        "println('Name: ' %2B aSlave.name);"
                                        "println('RemoteFS: ' %2B aSlave.getRemoteFS());"\
                                        "println('Mode: ' %2B aSlave.getMode());"\
                                        "println('RootPath: ' %2B aSlave.getRootPath());"\
                                        "println('Offline: ' %2B aSlave.getComputer().isOffline());"\
                                        "println('Launch Supported: ' %2B aSlave.getComputer().isLaunchSupported());"\
                                        "}")
                try:
                    c.perform()
                except pycurl.error, e:
                    errno, errstr = e
                    print '[!] Error ' + errstr
                    return False
                c.setopt(c.POSTFIELDS, "script=for (aSlave in hudson.model.Hudson.instance.slaves) {"\
                                        "println(aSlave.name);}")
                c.setopt(c.WRITEFUNCTION, buf.write)
                try:
                    c.perform()
                    cnodes = buf.getvalue().split('\n')
                except pycurl.error, e:
                    errno, errstr = e
                    print '[!] Error ' + errstr + ' filling nodes list!'
                    return False
            else:
                c = pycurl.Curl()
                c.setopt(c.URL, server + '/scriptText')
                c.setopt(c.POSTFIELDS, "script=for (aSlave in hudson.model.Hudson.instance.slaves) {"\
                                        "println('====================');"\
                                        "println('Name: ' %2B aSlave.name);"
                                        "println('RemoteFS: ' %2B aSlave.getRemoteFS());"\
                                        "println('Mode: ' %2B aSlave.getMode());"\
                                        "println('RootPath: ' %2B aSlave.getRootPath());"\
                                        "println('Offline: ' %2B aSlave.getComputer().isOffline());"\
                                        "println('Launch Supported: ' %2B aSlave.getComputer().isLaunchSupported());"\
                                        "}")
                try:
                    c.perform()
                except pycurl.error, e:
                    errno, errstr = e
                    print '[!] Error ' + errstr
                    return False
                c.setopt(c.POSTFIELDS, "script=for (aSlave in hudson.model.Hudson.instance.slaves) {"\
                                        "println(aSlave.name);}")
                c.setopt(c.WRITEFUNCTION, buf.write)
                try:
                    c.perform()
                    cnodes = buf.getvalue()
                except pycurl.error, e:
                    errno, errstr = e
                    print '[!] Error ' + errstr + ' filling nodes list!'
                    return Flase

        
    def help_nodes(self):
        print "\nDisplay any nodes that are available on the remote "\
                "Jenkins server.\n"


    def do_node(self, line):
        global cnode
        if connected is True:
            i = CommandShell()
            try:
                cnode = line.split()[0]
            except Exception, e:
                print '[!] You must specify a Node!'
                return False
            if cnode in cnodes: 
                i.prompt = "Node:" + cnode + ">"
                i.intro = "\nYou are now accessing the Node " + cnode + ""\
                            "\n"
                i.cmdloop()
            else:
                print '[!] Error: Node not found on server'
                return False
        else:
            print '[!] You must connect to server first!'


    def help_node(self):
        print "\nSwitch from Jenkins server to a Jenkins Node.\n"


    def do_command(self, line):
        if connected is False:
            print '[!] You must connect to a server first!'
        else:
            if authenticated is True:
                if cnode is None:
                    c = pycurl.Curl()
                    c.setopt(c.URL, server + '/scriptText')
                    c.setopt(c.USERPWD, auth)
                    c.setopt(c.POSTFIELDS, 'script=println "' + line + '".execute().text')
                    try:
                        output = c.perform()
                    except pycurl.error, e:
                        errno, errstr = e
                        print '[!] Error ' + errstr
                        return False
                    finally:
                        print str(output).strip('None\n')
                else:
                    c = pycurl.Curl()
                    c.setopt(c.URL, server + '/computer/' + cnode + '/scriptText')
                    c.setopt(c.USERPWD, auth)
                    c.setopt(c.POSTFIELDS, 'script=println"' + line + '".execute().text')
                    try:
                        c.perform()
                    except pycurl.error, e:
                        errno, errstr = e
                        print '[!] Error ' + errstr
                        return False
            else:
                if cnode is None:
                    c = pycurl.Curl()
                    c.setopt(c.URL, server + '/scriptText')
                    c.setopt(c.POSTFIELDS, 'script=println "' + line + '".execute().text')
                    try:
                        output = c.perform()
                    except pycurl.error, e:
                        errno, errstr = e
                        print '[!] Error ' + errstr
                        return False
                    finally:
                        print str(output).strip('None\n')
                else:
                    c = pycurl.Curl()
                    c.setopt(c.URL, server + '/computer/' + cnode + '/scriptText')
                    c.setopt(c.USERPWD, auth)
                    c.setopt(c.POSTFIELDS, 'script=println"' + line + '".execute().text')
                    try:
                        c.perform()
                    except pycurl.error, e:
                        errno, errstr = e
                        print '[!] Error ' + errstr
                        return False


    def do_shell(self, s):
        subprocess.run(s, shell=False, check=True, text=True)


    def __init__(self):
        cmd.Cmd.__init__(self)
        self.intro = "\nThis command shell is provided to interface with a "\
                        "remote Jenkins Server.\n\nCommands Available:\n"\
                        "connect ------ connect to Jenkins Server\n"\
                        "ps ----------- display all processes running on server or node\n"\
                        "whoami ------- display user on server or node\n"\
                        "users -------- display all user accounts on server or node\n"\
                        "ssh-creds ---- display user ssh key if available\n"\
                        "mounts ------- display all mounted devices\n"\
                        "shell -------- execute local commands\n"\
                        "command ------ execute remote commands\n"\
                        "nodes -------- list all Jenkins nodes\n"\
                        "node --------- connect to node\n"\
                        "help --------- display help\n"\
                        "exit --------- exit\n"\
                        " $ ------------- same as shell command\n"\
                        " @ ------------- same as command command\n"\
                        " ? ------------- same as help command\n\n"\
                        "To see a list of all commands use ? or help\n\n"
        self.prompt = "leroy jenkins>"

    
    def can_exit(self):
        return True
        

    def do_exit(self, s):
        return True


    def help_exit(self):
        print "\nExit the interpreter."
        print "You can also use the Ctrl-D shortcut\n"


    def emptyline(self):
        pass


    def help_command(self):
        print "\nUsage: Once connected use this to pass commands to remote"\
                " Jenkins server\n"


    def help_shell(self):
        print "\nUsage: Use the bash shell commands\n"


    def help_help(self):
        print "\nDisplay the commands that are available\n"


    def onecmd(self, line):
        if line[:1] is '$':
            line = 'shell '+ line[1:]
        elif line[:1] is '@':
            line = 'command ' + line[1:]
        elif re.match(r'ps', line, re.M|re.I):
            line = 'command ps -ef'
        elif re.match(r'users', line, re.M|re.I):
            line = 'command cat /etc/passwd'
        elif re.match(r'whoami', line, re.M|re.I):
            line = 'command id -a'
        elif re.match(r'mounts', line, re.M|re.I):
            line = 'command mount'
        elif re.search(r'fuck', line, re.M|re.I):
            print "I don't fuck. Sorry."
            return False
        elif re.search(r'shit', line, re.M|re.I):
            print "No cursing please."
            return False
        elif re.search(r'damn', line, re.M|re.I):
            print "No cursing please."
            return False
        elif re.match(r'cat', line, re.M|re.I):
            line = 'command cat ' + line.strip('cat')
        elif re.match(r'ls', line, re.M|re.I):
            line = 'command ls ' + line.strip('ls')
        elif re.match(r'pwd', line, re.M|re.I):
            line = 'command pwd'
        elif re.match(r'nc', line, re.M|re.I):
            line = 'command nc ' + line.strip('nc')
        elif re.match(r'which', line, re.M|re.I):
            line = 'command which ' + line.strip('which')
        elif re.match(r'find', line, re.M|re.I):
            line = 'command find ' + line.strip('find')
        elif re.match(r'ifconfig', line, re.M|re.I):
            line = 'command ifconfig ' + line.strip('ifconfig')
        r = super (CommandShell, self).onecmd(line)
        if r:
            r = raw_input('\nReally exit ?(y/n):')=='y'
        return r

    def help_commands(self):
        print '\nCommands Available:\n\n'\
                        "connect ------ connect to Jenkins Server\n"\
                        "ps ----------- display all processes running on server or node\n"\
                        "whoami ------- display user on server or node\n"\
                        "users -------- display all user accounts on server or node\n"\
                        "ssh-creds ---- display user ssh key if available\n"\
                        "mounts ------- display all mounted devices\n"\
                        "shell -------- execute local commands\n"\
                        "command ------ execute remote commands\n"\
                        "nodes -------- list all Jenkins nodes\n"\
                        "node --------- connect to node\n"\
                        "help --------- display help\n"\
                        "exit --------- exit\n"\
                        " $ ------------- same as shell command\n"\
                        " @ ------------- same as command command\n"\
                        " ? ------------- same as help command\n\n"\
                        "To see a list of all commands use ? or help\n"\
                        "There are some others available too!\n\n"


def main():
    parser = optparse.OptionParser(usage='%prog -g or --gui Runs the Graphical'\
                                    'interface. %prog runs the cli', 
                                    version='%prog Version 1.0')
    parser.add_option('-g', '--gui', dest='gui', action='store_true', help=''\
                        'Run the graphical interface.')
    (options, args) = parser.parse_args()
    gui = options.gui
    if gui is None:
        gui = False
    if gui is True:
        try:
            interface = Gui()
            gtk.main()
        except (KeyboardInterrupt):
            print '\n[-] Exiting ...'
    if gui is False:
        try:
            interpreter = CommandShell()
            interpreter.cmdloop()
        except (KeyboardInterrupt):
            print '\n[-] Exiting ... '


if __name__ == '__main__':
    main()

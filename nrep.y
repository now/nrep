#  TODO: try to simplify this a bit.  Perhaps we don’t have to be so fuzzy about
# all the arrays
# TODO: refactor Grepper and Output.  Some timesavings if more is known in
# Grepper.  (Maybe)
# Inverted guards: <!(ret)>/<not(ret)>
class RRep::Parser
rule
  regex         : { result = GuardedRegexp.new } # { result = ['', []] }
                | regex atom { 
                  result = val[0] << val[1]
#                  if val[1].is_a? Array 
#                    val[0][0] << val[1][0]
#                    val[0][1] << val[1][1]
#                  else
#                    val[0][0] << val[1]
#                  end
#                  result = val[0]
                }

  atom          : LITERAL
                | rule

  rule          : '<' IDENT parameters '>' {
                  rs = Rules[val[1]].call(*val[2])
                  case rs
                  when GuardedRegexp
                    result = rs
                  else
                    result = /#{rs}/.source
                  end
#                  if rs.is_a? Array
#                    result = GuardedRegexp.new(/#{rs[0]}/.source, rs[1]])
#                    result = [/#{rs[0]}/.source, rs[1]]
#                  else
#                    result = /#{rs}/.source
#                  end
                }
    #result = /#{Rules[val[1]].call(*val[2])}/.source }

  parameters    : { result = [] }
                | '(' parameterlist ')' { result = val[1] }

  parameterlist : regex { result = [val[0]] }
                | parameterlist ',' regex { result = val[0] << val[2] }
end

---- header ----

require 'optparse'
require 'ostruct'

$KCODE = 'u'

# TODO: perhaps GuardedRegexp and all this shoudn’t be here.  Perhaps the parse
# should be separate from the actual conversion, as we seem to be doing a lot
# of translations between Regexps and Strings and Guards and GuardedRegexps.
class Guard
  def initialize(gregex, inverted = false)
    @gregex, @inverted = gregex, inverted
#    @regex, @own_guards, @inverted = /#{regex[0]}/, regex[1], inverted
  end

  def match(s)
    if m = @gregex.regex.match(s)
      @inverted ? nil : m[0]
    else
      @inverted ? s : nil
    end
  end

  def own_guards
    @gregex.guards
  end

  def build
    @gregex.build
  end

#  attr_reader :own_guards
end

# TODO: this class can perhaps be used for all rules, with empty guards
# shouldn'9t @guards << other.guards be @guard.concat(other.guards)
class GuardedRegexp
  def initialize(regex = //, guards = [])
    @regex, @guards = /#{regex}/.source, guards
  end

  def <<(other)
    case other
    when GuardedRegexp
      # TODO: use other.regex here now, right?
      @regex << /#{other.regex}/.source
      @guards.concat(other.guards)
    when String
      @regex << other
    else
      p 'uhoh'
    end
    self
  end

  # TODO: a way to tell the regexp to build itself and stay this way:
  def build
    @regex = /#{regex}/
    @guards.each{ |guard| guard.build }
  end

  attr_accessor :regex, :guards
end


---- inner ----

  Rules = {
    'tag' => proc{ |tag, r| GuardedRegexp.new(/<#{tag.regex}(?:\s+\w+(?:="[^"\\]*(\\.[^"\\]*)*")?)*>.*?<\/#{tag.regex}>/m, [Guard.new(r)]) },
    'instring' => proc{ |r| GuardedRegexp.new(/"[^"\\]*(\\.[^"\\]*)*"/, [Guard.new(r)]) },
#    'tag' => proc{ |tag, r| [/<#{tag}(?:\s+\w+(?:="[^"\\]*(\\.[^"\\]*)*")?)*>.*?<\/#{tag}>/m, Guard.new(r)] },
#    'instring' => proc{ |r| [/"[^"\\]*(\\.[^"\\]*)*"/, Guard.new(r)] },
#    'tag' => proc{ |tag, r| [/<#{tag}(?:\s+\w+(?:="[^"\\]*(\\.[^"\\]*)*")?)*>.*?<\/#{tag}>/m, [/#{r[0]}/, r[1]]] },
#    'instring' => proc{ |r| [/"[^"\\]*(\\.[^"\\]*)*"/, [/#{r[0]}/, r[1]]] },
    'ws' => proc { /\s+/ }
  }

  # TODO: need to add escaping and better error-handling
  def tokenizer(str, toplevel = true)
    q = []

    until str.empty? or (not toplevel and str =~ /\A[,)]/) do
      case str
      when /\A</
        q.push [$&, $&]
        str = $'
        done = false
        until done or str.empty? do
          case str
          when /\A>/
            q.push [$&, $&]
            done = true
          when /\A\w+/
            q.push [:IDENT, $&]
            str = $'
            if str =~ /\A\(/
              q.push [$&, $&]
              str = $'
              innerdone = false
              until innerdone or str.empty? do
                case str
                when /\A\)/
                  q.push [$&, $&]
                  innerdone = true
                when /\A,/ # TODO: (?:\s*)/
                  q.push [',', ',']
                else
                  a, str = tokenizer(str, false)
                  q.concat(a)
                  next
                end
                str = $'
              end
            else
              next
            end
          else
            raise "can’t lex beginning at #{str}"
          end
          str = $'
        end
      else
        c = str[0, 1]
        q.push [:LITERAL, c]
        str = str[1..-1]
        next
      end
      str = $'
    end
    
    [q, str]
  end

  def parse(str)
    @q, _ = tokenizer(str)

    @q.push [false, '$end']

    do_parse
  end

  def next_token
    @q.shift
  end

---- footer ----

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_ERROR = 2

ApplicationName = File.basename($0)

class Messenger
  DefaultRoutine = proc{ |io, whoami, message| io.print whoami, ': ', message, "\n" }
  PlainRoutine = proc{ |io, _, message| io.puts message }

  def initialize(io = $stderr, whoami = File.basename($0), &routine)
    @io, @whoami = io, whoami
    @routine = block_given? ? routine : DefaultRoutine
  end

  def plain
    real = @routine
    @routine = PlainRoutine
    yield self
  ensure
    @routine = real
  end

  def info(message)
    @routine.call(@io, @whoami, message)
  end

  alias_method :nonfatal, :info

  def suppressable(message)
    nonfatal(message) unless $options.no_messages
  end

  def fatal(message)
    nonfatal(message)
    exit EXIT_ERROR
  end
end

$messenger = Messenger.new

$options = OpenStruct.new
$options.color = :never
$options.count = false
$options.regexp_options = 0
$options.filename_selection = nil
$options.max = -1
$options.line_number = false
$options.with_filename = false
$options.filename_header = nil
$options.only_matching = false
$options.label = nil
$options.quiet = false
$options.no_messages = false
$options.invert_match = false
$options.binary = :binary
$options.filename_mask = ~0
$options.mmap = false
$options.null_data = false
$options.regexp_before = $options.regexp_after = ''
$options.regexp = nil
$options.line_buffered = false
$options.include = []
$options.exclude = []
$options.devices = :read
$options.directories = :read

opts = OptionParser.new do |opts|
  opts.banner = <<EOB
Usage: #{ApplicationName} [OPTION]... PATTERN [FILE]...
   or: #{ApplicationName} --pattern=PATTERN [FILE]...
   or: #{ApplicationName} --file=FILE [FILE]...
Search for PATTERN in each FILE or standard input.
Example: nrep 'looking for gold' /dev/high /dev/low /dev/nose
EOB

  opts.separator ''
  opts.separator 'Regex Interpretation:'

  opts.on('-e', '--regexp=PATTERN', '--pattern=PATTERN',
          'use PATTERN as a regular expression') do |regexp|
    $options.regexp = regexp
  end

  opts.on('-f', '--file=FILE', 'obtain PATTERN from FILE') do |file|
    begin
      $options.regexp = IO.read(file).chomp!
    rescue Errno::ENOENT, Errno::EACCES => e
      $messenger.fatal("#{path}: #{e.message.sub(/\s+-\s+.*$/, '')}")
    end
  end

  opts.on('-i', '--ignore-case', 'ignore case distinctions') do
    $options.regexp_options = Regexp::IGNORECASE
  end

  opts.on('-w', '--word-regexp', 'force PATTERN to match only whole words') do
    $options.regexp_before = '\b(?:'
    $options.regexp_after = ')\b'
  end

  opts.on('-x', '--line-regexp', 'force PATTERN to match only whole lines') do
    $options.regexp_before = '^(?:'
    $options.regexp_after = ')$'
  end

  opts.on('-z', '--null-data', 'a data line ends in 0 byte, not newline') do
    $options.null_data = true
  end

  opts.separator ''
  opts.separator 'Miscellaneous:'

  opts.on('-s', '--no-messages', 'suppress error messages') do
    $options.no_messages = true
  end

  opts.on('-v', '--invert-match', 'select non-matching lines') do
    $options.invert_match = true
  end

  opts.on('-V', '--version', 'display version information and exit') do
    puts <<EOV
nrep 1.0.0

Copyright © 2005 Nikolai Weibull <nikolai@bitwi.se>
EOV
    exit
  end

  opts.on('--help', 'display this help and exit') do
    puts opts
    puts <<EOH

‘nrep’ means ‘nrep’.  Let’s leave it at that.
With no FILE, or when FILE is -, read standard input.  If less than
two files given, assume -h.  Exit status is 0 if match, 1 if no match,
and 2 if trouble.

Report bugs to <nikolai+work.bugs@bitwi.se>.
EOH
    exit
  end

  opts.on('--mmap', 'use memory-mapped input if possible (which it isn’t)') do
    $options.mmap = true
  end


  opts.separator ''
  opts.separator 'Output Control:'

  opts.on('-m', '--max-count=NUM', Integer, 'stop after NUM matches') do |max|
    $options.max = max
  end

  opts.on('-n', '--line-number', 'print line number with output lines') do
    $options.line_number = true
  end

  opts.on('--line-buffered', 'flush output on every line') do
    $options.line_buffered = true
  end

  opts.on('-H', '--with-filename', 'print the filename for each match') do
    $options.with_filename = true
  end

  opts.on('-h', '--no-filename', 'print the filename for each match') do
    $options.with_filename = false
  end

  opts.on('--label=LABEL',
          'print LABEL as filename for standard input') do |label|
    $options.label = label
  end

  opts.on('--filename-header[=INDENT]', Integer,
          'print the filename once for each FILE with matches') do |indent|
    $options.filename_header = ' ' * (indent or 2)
  end

  opts.on('-o', '--only-matching',
          'show only the part of a line matching PATTERN') do
    $options.only_matching = true
  end

  opts.on('-q', '--quiet', '--silent', 'suppress all normal output') do
    $options.quiet = true
  end

  TYPES = ['binary', 'text', 'without-match']
  opts.on('--binary-files=TYPE', TYPES, 'assume that binary files are TYPE',
          "TYPE is ‘binary’, ‘text’, or ‘without-match’") do |type|
    $options.binary = type == 'without-match' ? :without : type.intern
  end

  opts.on('-a', '--text', 'equivalent to --binary-files text') do
    $options.binary = :text
  end

  opts.on('-I', 'equivalent to --binary-files without-match') do
    $options.binary = :without
  end

  DIRECTORIES_ACTIONS = ['read', 'recurse', 'skip']
  opts.on('-d', '--directories=ACTION', DIRECTORIES_ACTIONS,
          'how to handle directories',
          'ACTION is ‘read’, ‘recurse’, or ‘skip’') do |action|
    $options.directories = action.intern
  end

  DEVICES_ACTIONS = ['read', 'skip']
  opts.on('-D', '--devices=ACTION', DEVICES_ACTIONS,
          'how to handle devices, FIFOs, and sockets',
          'ACTION is ‘read’ or ‘skip’') do |action|
    $options.devices = action.intern
  end

  opts.on('--include=PATTERN',
          'files that match PATTERN will be examined') do |pattern|
    $options.include << pattern
  end

  opts.on('--exclude=PATTERN',
          'files that match PATTERN will be skipped') do |pattern|
    $options.exclude << pattern
  end

  opts.on('--exclude-from=FILE',
          'files that match PATTERN in FILE will be skipped') do |path|
    begin
      IO.foreach(path){ |pattern| $options.exclude << pattern }
    rescue Errno::ENOENT, Errno::EACCES => e
      $messenger.fatal("#{path}: #{e.message.sub(/\s+-\s+.*$/, '')}")
    end
  end

  opts.on('-L', '--files-without-match',
          'only print FILE names containing no match') do
    $options.filename_selection = :without
  end

  opts.on('-l', '--files-with-matches',
          'only print FILE names containing matches') do
    $options.filename_selection = :with
  end

  opts.on('-c', '--count', 'only print a count of matching lines per FILE') do
    $options.count = true
  end

  opts.on('-Z', '--null', 'print 0 byte after FILE name') do
    $options.filename_mask = 0
  end

  opts.separator ''
  opts.separator 'Context Control:'

  COLOR_WHEN = ['auto', 'always', 'never']
  opts.on('--color[=WHEN]',     '--colour[=WHEN]',  '--farbe[=WHEN]',
          '--couleur[=WHEN]',   '--farve[=WHEN]',   '--färg[=WHEN]',
          '--väri[=WHEN]',      '--kleur[=WHEN]',   '--colore[=WHEN]',
          '--koloro[=WHEN]',    '--farge[=WHEN]',   '--barwa[=WHEN]',
          '--cor[=WHEN]',       '--barva[=WHEN]',   '--klöör[=WHEN]',
          '--palli[=WHEN]',     '--barva[=WHEN]',   '--warna[=WHEN]',
          '--цвят[=WHEN]',      '--szín[=WHEN]',    '--culuri[=WHEN]',
          '--renk[=WHEN]',      '--coleur[=WHEN]',  '--spalva[=WHEN]',
          '--màu-sắc[=WHEN]',   '--цвет[=WHEN]',
          COLOR_WHEN,
          'use markers to distinguish the matching string',
          'WHEN may be ‘auto’, ‘always’, or ‘never’') do |w|
    $options.color = w ? w.intern : :auto
    accessible = $stdout.tty? and ENV['TERM'] and ENV['TERM'] !~ /dumb/
    $options.color = accessible ? :always : :never if $options.color == :auto
  end
end

class Output
  def initialize
    @color, @reset = $options.color == :always ? [`tput setab 11`, `tput sgr0`] : ['', '']
    @ls_colors = LSColors.new
    $stdout.sync = $options.line_buffered
  end

  def opening(path)
    @path = path
    @is_binary = false
    @matches = 0
  end

  def is_binary=(buf)
    if buf.index("\0")
      throw :done if $options.binary == :without
      @is_binary = true
    end
  end

  def line(line, before, match, after)
    exit if $options.quiet
    @matches += 1
    unless $options.count or $options.filename_selection
      before = after = '' if $options.only_matching
      if @is_binary and $options.binary == :binary
        puts "Binary file #{@path} matches"
        throw :done
      else
        if $options.filename_header
          print @ls_colors.path(@path), ":\n" if @matches == 1
          print $options.filename_header
        elsif $options.with_filename
          print_path(?:)
        end
        print line, ':' if $options.line_number
        print before, @color, match, @reset, after
      end
    end
    if $options.filename_selection == :with
      print_path(?\n)
      throw :done
    end
  end

  attr_reader :matches

  def closing
    print_path(?\n) if $options.filename_selection == :without and @matches == 0
    puts @matches if $options.count
  end

private
  
  def print_path(sep)
    print @path, (sep & $options.filename_mask).chr
  end
end

class LSColors
  Specials = {
    'lc' => "\e[",
    'rc' => 'm',
    'ec' => nil,
    'no' => '0',
    'fi' => '0',
    'di' => '01;34',
    'ln' => '01;36',
    'pi' => '33',
    'so' => '01;35',
    'cd' => '01;33',
    'bd' => '01;33',
    'or' => nil,
    'ex' => '01;32',
    'do' => '01;35',
    'su' => '37;41',
    'sg' => '30;43',
    'wo' => '37;44',
    'wt' => '37;42'
  }

  def initialize
    mappings = ENV["LS_COLORS"].split(/:/).map{ |s| s.split(/=/) }
    specials, @extensions = mappings.partition{ |p, _| Specials.include? p }
    @specials = Specials.merge(specials.inject({}){ |h, p| h.store(*p); h })
  end 

  def path(path)
    if color = self.for(path)
      encode(color) + path + (@specials['ec'] or encode(@specials['no']))
    else
      path
    end
  end

  attr_reader :specials

  def for(path)
    path = File.basename(path)
    e = @extensions.find{ |e, _| File.fnmatch(e, path, File::FNM_PATHNAME) }
    return e[1] if e
    case
    when File.setgid?(path): @specials['sg']
    when File.setuid?(path): @specials['su']
    when File.blockdev?(path): @specials['bd']
    when File.chardev?(path): @specials['cd']
    when File.directory?(path)
      mode = File.stat(path).mode rescue 0
      if mode & 01002
        @specials['wt']
      elsif mode & 02
        @specials['wo']
      else
        @specials['di']
      end
    when File.symlink?(path): File.exist?(path) ? @specials['or'] : @specials['ln']
    when File.file?(path): File.executable?(path) ? @specials['ex'] : @specials['fi']
    when File.pipe?(path): @specials['pi']
    when File.socket?(path): @specials['so']
    else
      ((File.stat(path).mode rescue 0) & 0150000) ? @specials['do'] : @specials['no']
    end
  end

private

  def encode(color)
    @specials['lc'] + color + @specials['rc']
  end
end

class Grepper
  def initialize(output, regex)
    @eol = $options.null_data ? "\0" : "\n"
    @output = output
    @regex = regex.regex
    @guards = regex.guards
  end

  def grep(file)
    reset
    catch :done do
      until file.eof?
        buf = fetch(file)
        while buf =~ @regex
          throw :done if $options.max >= 0 and matches >= $options.max
          buf = report($~)
          throw :done if $options.max >= 0 and matches >= $options.max
        end
        # TODO: actually, this should be put into @residue, as there may be a
        # match that goes beyond a single line
        if $options.invert_match
          report_lines(buf)
        else
          @line += buf.count("\n")
        end
      end
    end
    @output.matches
  end

private
  
  def reset
    @first_batch = true
    @residue = ''
    @line = 1
  end

  def fetch(file)
    buf = @residue
    buf << file.read(65536)
    @output.is_binary = buf if @first_batch
    @first_batch = false
    @residue = (i = buf.rindex(@eol)) ? buf.slice!(i + 1, buf.size - (i + 1)) : ''
    buf
  end

  def report_lines(s)
    s.each do |line|
      @output.line(@line, line, '', '')
      @line += 1
    end
  end

  # TODO: need to advance @line with number of newlines in m[0] (because we can
  # be matching them in nrep).
  def report(m)
    send($options.invert_match ? :report_inv : :report_s, m)
  end

  def report_s(m)
    @line += m.pre_match.count(@eol)
    before = (i = m.pre_match.rindex(@eol)) ? m.pre_match[(i + 1)..-1] : m.pre_match
    after = (i = m.post_match.index(@eol)) ? m.post_match[0..i] : m.post_match
    @output.line(@line, before, m[0], after) if passes_guards(@guards, m[0])
    advance(m, i)
  end

  def report_inv(m)
    report_lines(m.pre_match)
    advance(m, m.post_match.index(@eol))
  end
  
  def passes_guards(guards, match)
    not guards.find{ |guard| (not (m = guard.match(match))) or (not passes_guards(guard.own_guards, m)) }
  end

  def advance(m, i)
    i ? m.post_match[(i + 1)..(m.post_match.size - (i + 1))] : m.post_match
  end
end

class Runner
  def initialize(regex)
    @output = Output.new
    @found_line = @had_errors = false
    @grepper = Grepper.new(@output, regex)
    @directories = Hash.new{ [] }
  end

  def execute(paths)
    run(paths)
    status = @found_line ? EXIT_SUCCESS : EXIT_FAILURE
    status = (@had_errors and not ($options.quiet and @found_line)) ? EXIT_ERROR : status
    exit status
  end

private

  def run(paths)
    paths.each do |path|
      next unless $options.include.find{ |pattern| File.fnmatch(pattern, path) } if $options.include.size > 0
      next if $options.exclude.find{ |pattern| File.fnmatch(pattern, path) }
      next if $options.devices == :skip and (File.blockdev?(path) or File.chardev?(path) or File.socket?(path))
      if File.directory? path
        perhaps_open_dir(path)
      else
        open(path){ |file| @found_line = true if @grepper.grep(file) > 0 }
      end
    end
  end

  def open(path)
    file = if path == '-'
             path = $options.label or '(standard input)'
             $stdin
           else
             File.open(path)
           end
    @output.opening(path)
    yield file
    @output.closing
  rescue Errno::ENOENT, Errno::EACCES => e
    @had_errors = true
    $messenger.suppressable("#{path}: #{e.message.sub(/\s+-\s+.*$/, '')}")
  rescue Errno::EISDIR
    perhaps_open_dir(path)
  ensure
    file.close if file
  end

  def perhaps_open_dir(path)
    return unless $options.directories == :recurse
    begin
      st = File.stat(path)
    rescue => e
      @had_errors = true
      $messenger.suppressable("#{path}: #{e.message.sub(/\s+-\s+.*$/, '')}")
      return
    end
    if st.ino > 0 and @directories[st.dev].include? st.ino
      $messenger.suppressable("warning: #{path}: recursive directory loop")
    else
      @directories[st.dev].push st.ino
      run(Dir.entries(path).reject{ |p| p =~ /^\.{1,2}$/ }.map{ |p| File.join(path, p) })
      @directories[st.dev].pop
    end
  end
end

def usage(opts)
  $messenger.plain do |m|
    m.info opts.banner.sub(/\n.*$/m, '')
    m.info 'Try ‘nrep --help’ for more information.'
  end
  exit EXIT_ERROR
end

begin
  opts.parse!(ARGV)
  unless $options.regexp
    usage(opts) if ARGV.size == 0
    $options.regexp = ARGV.shift
  end
  regex = RRep::Parser.new.parse($options.regexp)
  regex = GuardedRegexp.new(Regexp.new("#{$options.regexp_before}#{regex.regex}#{$options.regexp_after}", $options.regexp_options), regex.guards)
  regex.build
rescue => e
  $messenger.fatal(e.message)
end

$options.with_filename = true if ARGV.size > 1

ARGV.push('-') if ARGV.size == 0

Runner.new(regex).execute(ARGV)

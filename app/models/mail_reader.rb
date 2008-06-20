class MailReader < ActionMailer::Base

  def receive(email)         
    # Check if the user/author exists for the email. 
    # If they don't then create the user.
    
    author = User.find_by_mail @@from_email
    
    if author.nil?
      #create the user with minimal permissions and no email notifications
      author = User.new
      author.login = @@from_email.split('@')[0]
      author.status = 3 #set status to locked
      author.mail_notification = false
      author.firstname = @@from_name.split(" ")[0] #hope name is first then last
      author.lastname = @@from_name.split(" ")[1]
      author.auth_source_id = 1 #this is the AD auth for the current install
      author.mail = @@from_email
      
      begin 
        author.save
        puts "User created"
      rescue
        puts author.errors
        return false
      end
      
    end
    
    author_id = author.id

    ic = Iconv.new('UTF-8', 'UTF-8')
    
    priorities = Enumeration.get_values('IPRI')
    @DEFAULT_PRIORITY = priorities.find {|p| p.name == "Normal" }
    @PRIORITY_MAPPING = {}
    priorities.each { |priority| @PRIORITY_MAPPING[priority.name] = priority }

    tracker = Tracker.find_by_name(@@config[:issue_tracker])
    status = IssueStatus.find_by_name(@@config[:issue_status])
    
    tracker_id = tracker.id unless tracker.nil?
    status_id = status.id unless status.nil?

    #check if the email subject includes an issue id
    issue_id = email.subject.scan(/#(\d+)/).flatten

    #if issue_id found in email subject then try to find corresponding issue
    unless issue_id.empty?
      begin
        issue = Issue.find(issue_id[0])
      rescue
        puts "Issue #{issue_id[0]} not found"
      end
    end

    if issue.nil?
      #no issue id found in header => new issue to create
      puts "Creating new issue"
      issue = Issue.create(
          :subject => email.subject,                                          
          :description => email.body.split(/<(HTML|html)/)[0].gsub(/<\/?[^>]*>/, ''),
          :priority_id => @DEFAULT_PRIORITY.id, #@PRIORITY_MAPPING[@priority].id || @DEFAULT_PRIORITY.id,
          :project_id => @@project.id,
          :tracker_id => tracker_id,
          :author_id => author_id,
          :status_id => status_id
       )

      if !issue.save
        puts "Failed to create issue"
        puts issue.errors
        return false
      else  
        # send autoreply
        MailReader.deliver_autoreply(issue) if @@config[:email_autoreply] == true
      end

    else
      #using the issue found from subject, create a new note for the issue
      puts "Issue ##{issue.id} exists, adding comment by #{author.firstname}..."
      journal = Journal.new(:notes => ic.iconv(email.body.split(/<(HTML|html)/)[0]),
                      :journalized => issue,
                      :user => author);
      if(!journal.save)
        puts "Failed to add comment"
        return false
      end

    end
       
    if email.has_attachments?
        for attachment in email.attachments        
            Attachment.create(:container => issue, 
              :file => attachment,
              :description => "",
              :author_id => author_id)
        end
    end

  end
  
  def self.check_mail
  
    begin
      require 'net/imap'
    rescue LoadErroremail_folder
      raise RequiredLibraryNotFoundError.new('NET::Imap could not be loaded')
    end

    @@config_path = (RAILS_ROOT + '/config/emailer.yml')
     
    # Cycle through all of the projects created in the yaml file       
    YAML.load_file(@@config_path).each_value do |config_group|

      #convert keys from strings to symbols
      @@config = config_group.symbolize_keys
      
      #find the project identifier relating to this config group
      project_identifier = @@config[:project_identifier]

      #Find the project based on the identifier in the YAML if the emailer is enabled in Redmine
      @@project = Project.find_by_identifier project_identifier, :include=>:enabled_modules, :conditions=>"enabled_modules.name='ticket_emailer'"

      unless @@project.nil?
        #create new IMAP instance
        imap = Net::IMAP.new(@@config[:email_server], port=@@config[:email_port], usessl=@@config[:use_ssl])

        #login, select folder and search for matching emails
        imap.login(@@config[:email_login], @@config[:email_password])
        imap.select(@@config[:email_folder])
        #search TO and CC fields
        imap.search(['OR', 'TO', @@config[:email_to], 'CC', @@config[:email_to]]).each do |message_id|
          msg = imap.fetch(message_id,'RFC822')[0].attr['RFC822']
          
          #get the emails "from"
          @@from_name, @@from_email = from_email_address(imap, message_id)
          
          # if the email has no "from" email then the envelope has issues
          if @@from_email.nil?
            puts "Error with message envelope"
            
          #check if email matches whitelistings
          elsif @@config[:email_white_list].split(' ').find {|email_part| @@from_email.include? email_part}
            MailReader.receive(msg)
            
          # ignore non-whitelisted emails
          else
            puts "#{@@from_email} not whitelisted."
          end
          
          #Mark message as deleted and it will be removed from storage when imap session closed
          imap.store(message_id, "+FLAGS", [:Deleted])
        end
        
        # tell server to permanently remove all messages flagged as :Deleted
        imap.expunge()
      end
    end
  end
  
  def autoreply issue
    
    email_to = issue.author.mail

    redmine_headers 'Project' => issue.project.identifier,
                    'Issue-Id' => issue.id,
                    'Issue-Author' => issue.author.login
    redmine_headers 'Issue-Assignee' => issue.assigned_to.login if issue.assigned_to

    r = issue.recipients
    r << email_to unless email_to.nil?
    recipients r.uniq

    #use trackers email, otherwise redmine system-wide email address is used
    from(@@config[:email_primary]) unless @@config[:email_primary].nil?

    # Watchers in cc. NOTE: current implementation will have no watchers
    cc(issue.watcher_recipients - @recipients)

    s = "[XXX Support ##{issue.id}] "
    s << issue.subject
    subject s
    body :issue => issue,
         :author => issue.author,
         :tracker => issue.tracker.name.downcase
     
  end
  
  def attach_files(obj, attachment)
    attached = []
    user = User.find 2
    if attachment && attachment.is_a?(Hash)
        file = attachment['file']
            Attachment.create(:container => obj, 
                                  :file => file,
                                  :author => user)
        attached << a unless a.new_record?
    end
    attached
  end
  
  def self.from_email_address(imap, msg_id) 
    env = imap.fetch(msg_id, "ENVELOPE")[0].attr["ENVELOPE"]
    begin
      mailbox = env.from[0].mailbox
      host    = env.from[0].host
      name    = env.from[0].name
      from = "#{name}", "#{mailbox}@#{host}"
    rescue #return a nil for any error
      from = nil 
    end
  end
  
  private
  
  # Appends a Redmine header field (name is prepended with 'X-Redmine-')
  def redmine_headers(h)
    h.each { |k,v| headers["X-Redmine-#{k}"] = v }
  end
  
end

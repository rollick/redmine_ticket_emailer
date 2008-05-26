class MailReader < ActionMailer::Base

  def receive(email)         
    # If the email exists for a user in the current project,
    # use that user as the author.  Otherwise, use the first
    # user that is returned from the Member model
    
    # author = User.find_by_mail @@from_email, :select=>"users.id", :joins=>"inner join members on members.user_id = users.id",
    #                           :conditions=>["members.project_id=?", @@project.id]
    author = User.find_by_mail @@from_email
    
    if author.nil?
      #create the user with minimal permissions and no email notifications
      author = User.new
      author.login = @@from_email.split('@')[0]
      author.status = 3 #set status to locked
      author.mail_notification = false
      author.firstname = @@from_name.split(" ")[0] #hope name is first then last
      author.lastname = @@from_name.split(" ")[1]
      author.auth_source_id = 1 #this is the MEDDENT auth for the current install
      author.mail = @@from_email
      
      if author.save
        p "User created"
      else
        p author.errors
      end
      
    end
    
    author_id = author.id

    priorities = Enumeration.get_values('IPRI')
    @DEFAULT_PRIORITY = priorities.find {|p| p.name == "Normal" }
    @PRIORITY_MAPPING = {}
    priorities.each { |priority| @PRIORITY_MAPPING[priority.name] = priority }

    tracker_id = status_id = nil
    tracker_id = Tracker.find_by_name(@@config[:issue_tracker]).id unless Tracker.find_by_name(@@config[:issue_tracker]).nil?
    status_id = IssueStatus.find_by_name(@@config[:issue_status]).id unless IssueStatus.find_by_name(@@config[:issue_status]).nil?

    issue = Issue.create(
        :subject => email.subject,
#        :description => email.body.gsub(/<(html|HTML)[^<]*<\/(html|HTML)>/im,''),
        :description => email.body.split(/<(HTML|html)/)[0],
        :priority_id => @DEFAULT_PRIORITY.id, #@PRIORITY_MAPPING[@priority].id || @DEFAULT_PRIORITY.id,
        :project_id => @@project.id,
        :tracker_id => tracker_id,
        :author_id => author_id,
        :status_id => status_id        
    )
    
    if issue.save
      p issue.to_s
    else
      p issue.errors
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
      YAML.load_file(@@config_path).keys.each do |config_group|
     
         #find the project relating to this config group
         project_name = YAML.load_file(@@config_path)[config_group]["project"]
         
         #Find the project based off the name in the YAML if the emailer is enabled in Redmine
         @@project = Project.find_by_name project_name, :include=>:enabled_modules, :conditions=>"enabled_modules.name='ticket_emailer'"
        
         unless @@project.nil?

            #match yaml sections with a "project" key
            @@config = YAML.load_file(@@config_path)[config_group].symbolize_keys

            imap = Net::IMAP.new(@@config[:email_server], port=@@config[:email_port], usessl=@@config[:use_ssl])
         
            imap.login(@@config[:email_login], @@config[:email_password])
            imap.select(@@config[:email_folder])  
            imap.search(['TO', @@config[:email_to]]).each do |message_id|
               msg = imap.fetch(message_id,'RFC822')[0].attr['RFC822']
              @@from_name, @@from_email = from_email_address(imap, message_id)
              #check if email matches whitelistings
              if @@config[:email_white_list].split(' ').find {|email_part| @@from_email.include? email_part}
                MailReader.receive(msg)
              else
                p "#{@@from_email} not whitelisted."
              end   
              #Mark message as deleted and it will be removed from storage when user session closd
              imap.store(message_id, "+FLAGS", [:Deleted])
            end
            # tell server to permanently remove all messages flagged as :Deleted
            imap.expunge()
        end
    end
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
    mailbox = env.from[0].mailbox
    host    = env.from[0].host
    name    = env.from[0].name
    from = "#{name}", "#{mailbox}@#{host}"
  end
end

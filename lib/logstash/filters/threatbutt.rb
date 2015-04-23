# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "json"

# This example filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::Threatbutt < LogStash::Filters::Base

  config_name "threatbutt"
  
  # For filed containing the item to lookup. This can point to a field ontaining a File Hash or URL
  config :field, :validate => :string, :required => true

  # Lookup type
  config :lookup_type, :validate => :string, :default => "ip"

  # Where you want the data to be placed
  config :target, :validate => :string, :default => "threatbutt"

  public
  def register
    require "faraday"
  end # def register

  public
  def filter(event)

    if @lookup_type == "hash"
      url = "http://threatbutt.io/api/md5/" + event[@field]
      response = Faraday.post url
    elsif @lookup_type == "ip"
      url = "http://threatbutt.io/api"  
      response = Faraday.post url, { :ip => event[@field] }
    end
    result = JSON.parse(response.body)
    event[@target] = result

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Example

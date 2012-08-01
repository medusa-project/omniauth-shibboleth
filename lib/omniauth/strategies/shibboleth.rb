module OmniAuth
  module Strategies
    class Shibboleth
      include OmniAuth::Strategy

      option :uid_field, :eppn
      option :fields, [:name, :email]
      option :extra_fields, []
      option :debug, false

      def request_phase
        [
            302,
            {
                'Location' => script_name + callback_path + query_string,
                'Content-Type' => 'text/plain'
            },
            ["You are being redirected to Shibboleth SP/IdP for sign-in."]
        ]
      end

      def callback_phase
        if options[:debug]
          # dump attributes
          return [
              200,
              {
                  'Content-Type' => 'text/plain'
              },
              [request.env.sort.map { |i| "#{i[0]}: #{i[1]}" }.join("\n")]
          ]
        end
        return fail!(:no_shibboleth_session) unless (get_attribute('Shib-Session-ID') || get_attribute('Shib-Application-ID'))
        super
      end

      def get_attribute(name)
        request.env[header_name(name)]
      end

      def header_name(name)
        corrected_name = name.gsub('-', '_').upcase!
        "HTTP_#{corrected_name}"
      end

      uid do
        get_attribute(options.uid_field.to_s)
      end

      info do
        options.fields.inject({}) do |hash, field|
          case field
            when :name
              hash[field] = get_attribute('displayName')
            when :email
              hash[field] = get_attribute('mail')
            else
              hash[field] = get_attribute(field.to_s)
          end
          hash
        end
      end

      extra do
        options.extra_fields.inject({:raw_info => {}}) do |hash, field|
          hash[:raw_info][field] = get_attribute(field.to_s)
          hash
        end
      end

    end
  end
end

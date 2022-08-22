#pragma once

#include <stdio.h>
#include <string>
#include <vector>

namespace auth
{
    namespace provider {
        std::string salt();
        std::string hash( const std::string &text );
        unsigned long long now();
        unsigned long long expire_time();
    };

    class session
    {
        bool valid = 0;
        size_t timestamp = 0;
        std::string user, pass, id, public_key, passphrase;

        public:

            session() {
                set_public_key( std::string() );
            }

            explicit
            session( const std::string &name, const std::string &pass, const std::string &context = std::string(), const std::string &public_key = std::string() ) {
                setup( name, pass, context, public_key );
            }

            void setup( const std::string &name, const std::string &pass, const std::string &context = std::string(), const std::string &public_key = std::string() ) {
                this->user = name;
                this->id = user + ';' + context;
                this->pass = provider::hash( pass );
                set_public_key( public_key.empty() ? provider::salt() : public_key );
            }

            void touch() {
                timestamp = provider::now();
            }

            bool is_timedout() const {
                return( provider::now() > timestamp + provider::expire_time() );
            }

            bool is_valid() const {
                return valid;
            }

            void invalidate() {
                valid = false;
            }

            void reset() {
                valid = true;
                passphrase = public_key;
                mutate();
            }

            void mutate() {
                touch();
                passphrase = provider::hash( passphrase + pass );
            }

            std::string get_user_id() const {
                return id;
            }
            std::string get_user_name() const {
                return user;
            }

            std::string get_passphrase() const {
                return passphrase;
            }
            std::string next_passphrase() {
                mutate();
                return passphrase;
            }

            void set_public_key( const std::string &public_key ) {
                // we *must* reset after setting a new public key.
                this->public_key = public_key;
                reset();
            }

            std::string get_public_key() {
                return public_key;
            }

            size_t get_timestamp() {
                return timestamp;
            }

            template<class T>
            friend inline T& operator <<( T &ostream, const session &self ) {
                return ostream <<
                    "[session:" << &self << "] {" << "\n" <<
                    ".valid=" << self.valid << "\n" <<
                    ".timestamp=" << self.timestamp << "\n" <<
                    ".id=" << self.id << "\n" <<
                    ".user=" << self.user << "\n" <<
                    ".pass=" << self.pass << "\n" <<
                    ".public_key=" << self.public_key << "\n" <<
                    ".passphrase=" << self.passphrase << "\n" <<
                    "}" << "\n", ostream;
            }

            bool operator<( const session &other ) const {
                return id < other.id;
            }
            bool operator==( const session &other ) const {
                return user == other.user
                    && public_key == other.public_key
                    && passphrase == other.passphrase
                    && valid == other.valid;
            }
            bool operator!=( const session &other ) const {
                return !operator==( other );
            }
    };
}

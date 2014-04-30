--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET search_path = public, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: AccountSettings; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE "AccountSettings" (
    google_id character varying NOT NULL,
    send_nsfw boolean DEFAULT false NOT NULL,
    send_pm boolean DEFAULT true NOT NULL,
    nsfw_overrides character varying[] DEFAULT '{}'::character varying[] NOT NULL,
    post_limit integer DEFAULT 10 NOT NULL,
    group_posts boolean DEFAULT true NOT NULL
);


--
-- Name: GoogleAccount; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE "GoogleAccount" (
    id character varying NOT NULL,
    credentials bytea
);


--
-- Name: ImageUrlCache; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE "ImageUrlCache" (
    post_id character varying NOT NULL,
    url character varying,
    cached_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: RedditAccount; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE "RedditAccount" (
    id character varying NOT NULL,
    name character varying,
    google_id character varying,
    credentials bytea
);


--
-- Name: SentPost; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE "SentPost" (
    google_id character varying NOT NULL,
    post_id character varying NOT NULL
);


--
-- Name: SentPrivateMessage; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE "SentPrivateMessage" (
    google_id character varying NOT NULL,
    pm_id character varying NOT NULL
);


--
-- Name: AccountSettings_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY "AccountSettings"
    ADD CONSTRAINT "AccountSettings_pkey" PRIMARY KEY (google_id);


--
-- Name: GoogleAccount_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY "GoogleAccount"
    ADD CONSTRAINT "GoogleAccount_pkey" PRIMARY KEY (id);


--
-- Name: RedditAccount_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY "RedditAccount"
    ADD CONSTRAINT "RedditAccount_pkey" PRIMARY KEY (id);


--
-- Name: SentPost_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY "SentPost"
    ADD CONSTRAINT "SentPost_pkey" PRIMARY KEY (google_id, post_id);


--
-- Name: SentPrivateMessage_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY "SentPrivateMessage"
    ADD CONSTRAINT "SentPrivateMessage_pkey" PRIMARY KEY (google_id, pm_id);


--
-- Name: imageurlcache_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY "ImageUrlCache"
    ADD CONSTRAINT imageurlcache_pkey PRIMARY KEY (post_id);


--
-- Name: AccountSettings_google_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "AccountSettings"
    ADD CONSTRAINT "AccountSettings_google_id_fkey" FOREIGN KEY (google_id) REFERENCES "GoogleAccount"(id);


--
-- Name: RedditAccount_google_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "RedditAccount"
    ADD CONSTRAINT "RedditAccount_google_id_fkey" FOREIGN KEY (google_id) REFERENCES "GoogleAccount"(id);


--
-- Name: SentPost_google_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "SentPost"
    ADD CONSTRAINT "SentPost_google_id_fkey" FOREIGN KEY (google_id) REFERENCES "GoogleAccount"(id);


--
-- Name: public; Type: ACL; Schema: -; Owner: -
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;
GRANT ALL ON SCHEMA public TO narwhal;


--
-- Name: AccountSettings; Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON TABLE "AccountSettings" FROM PUBLIC;
REVOKE ALL ON TABLE "AccountSettings" FROM postgres;
GRANT ALL ON TABLE "AccountSettings" TO postgres;
GRANT ALL ON TABLE "AccountSettings" TO narwhal;


--
-- Name: GoogleAccount; Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON TABLE "GoogleAccount" FROM PUBLIC;
REVOKE ALL ON TABLE "GoogleAccount" FROM postgres;
GRANT ALL ON TABLE "GoogleAccount" TO postgres;
GRANT ALL ON TABLE "GoogleAccount" TO narwhal;


--
-- Name: RedditAccount; Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON TABLE "RedditAccount" FROM PUBLIC;
REVOKE ALL ON TABLE "RedditAccount" FROM postgres;
GRANT ALL ON TABLE "RedditAccount" TO postgres;
GRANT ALL ON TABLE "RedditAccount" TO narwhal;


--
-- Name: SentPost; Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON TABLE "SentPost" FROM PUBLIC;
REVOKE ALL ON TABLE "SentPost" FROM postgres;
GRANT ALL ON TABLE "SentPost" TO postgres;
GRANT ALL ON TABLE "SentPost" TO narwhal;


--
-- PostgreSQL database dump complete
--


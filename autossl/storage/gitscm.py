#!/usr/bin/env python
import logging
import os
import shutil

import git

from .. import exception, util
from . import base

logger = logging.getLogger(__name__)


def git_url_with_username_password(git_url, username, password):
    # This part handles git clone via http and not ssh. It is strongly advised to use
    # user/password combination when cloning in https. Most servers don't accept anonymous calls anymore
    if username and password:
        if 'http' in git_url:
            return git_url.replace('://', '://{}:{}@'.format(
                username, password
            ))
    else:
        return git_url


class GitStorage(base.Storage):

    def __init__(self, git_url, folder=None, tracking_record_id=None,
                 config_user_name=None, config_user_email=None, **kwargs):
        """Store data in git remote server

        :param git_url: full url of the repository to store data in
        :type git_url: str
        :param folder: path
        :type folder: pathlib.Path or str
        :param config_user_name: git config user name
        :type config_user_name: str
        :param config_user_email: git config user email
        :type config_user_email: str
        """
        super(GitStorage, self).__init__(tracking_record_id=tracking_record_id, **kwargs)
        self.folder = folder
        if folder is not None and not isinstance(folder, util.Path):
            self.folder = util.Path(folder)
        self.config_user_name = config_user_name
        self.config_user_email = config_user_email
        self.git_url = git_url_with_username_password(git_url,
                                                      kwargs.get('username'),
                                                      kwargs.get('password'))

    def save_data(self, name, content=None, local_path=None, **kwargs):
        with util.TempDir() as temp_folder:
            try:
                file_path, temp_file_path, git_repo = self.__clone(folder=temp_folder.path, name=name)

                # make sure parent folder and sub-folders exist
                parent_dir = temp_file_path.parent
                if not parent_dir.exists():
                    os.makedirs(str(parent_dir), mode=0o700)

                if content is not None:
                    # create file locally, as needed to push to remote repository
                    temp_file_path.write_bytes(content)
                else:
                    shutil.copy(str(local_path), str(temp_file_path))

                git_repo.git.add(file_path)

                # build commit message
                commit_message = 'File update {name}'.format(name=name)

                if self.tracking_record_id is not None:
                    commit_message += ' for tracking record {}'.format(self.tracking_record_id)

                # commit locally
                # allow-empty will still add commit message with new information even if data itself did not change
                git_repo.git.commit('--allow-empty', '-m', commit_message)

                # push changes remotely
                git_repo.git.push()

                logger.info("File {name} successfully saved".format(name=name))

            except git.exc.GitCommandError:
                logger.error("Unable to save file {name} to remote server.".format(name=name))
                raise

    def retrieve_data(self, name, **kwargs):
        with util.TempDir() as temp_folder:
            file_path, temp_file_path, repo = self.__clone(folder=temp_folder.path, name=name)
            if temp_file_path.is_file():
                return temp_file_path.read_bytes()
            else:
                raise exception.NotFound("File does not exist: {file_path}".format(file_path=file_path))

    def __clone(self, folder, name):
        # clone repository in local folder
        git_repo = git.Repo.clone_from(self.git_url, folder)

        # set user identity
        if self.config_user_name:
            git_repo.config_writer().set_value("user", "name", self.config_user_name).release()
        if self.config_user_email:
            git_repo.config_writer().set_value("user", "email", self.config_user_email).release()

        file_path = name
        if self.folder is not None:
            file_path = self.folder / name

        temp_file_path = folder / file_path

        return file_path, temp_file_path, git_repo

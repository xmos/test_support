@Library('xmos_jenkins_shared_library@v0.55.0') _

getApproval()

pipeline {
  agent {
    label 'x86_64 && linux'
  }
  environment {
    REPO = 'test_support'
  }
  options {
    skipDefaultCheckout()
  }
  stages {
    stage('Get view') {
      steps {
        dir(REPO) {
          checkout scm
        }
      }
    }
    stage('Library checks') {
      steps {
        runRepoChecks(REPO)
      }
    }
  }
  post {
    success {
      updateViewfiles()
    }
    cleanup {
      cleanWs()
    }
  }
}

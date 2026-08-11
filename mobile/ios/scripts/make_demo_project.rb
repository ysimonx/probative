#!/usr/bin/env ruby
# Génère le projet Xcode de l'application de démonstration.
#
# Le .xcodeproj n'est pas versionné : un pbxproj est illisible en revue et
# fusionne mal, alors que ce script décrit la même chose en clair. Les
# sources et ce fichier suffisent à reconstituer le projet à l'identique.
#
#   gem install xcodeproj && ruby scripts/make_demo_project.rb
#
# L'application n'existe que pour porter un App ID provisionné : App Attest
# refuse de fonctionner sans, y compris depuis un bundle de test XCTest.

require 'fileutils'
require 'xcodeproj'

ROOT = File.expand_path('..', __dir__)
DEMO = File.join(ROOT, 'demo')
PROJECT_PATH = File.join(DEMO, 'ProbativeDemo.xcodeproj')

# Équipe de signature : surchargeable pour qui reprend le dépôt.
TEAM = ENV.fetch('PROBATIVE_TEAM_ID', '9SGKL7VUD3')
BUNDLE_ID = ENV.fetch('PROBATIVE_BUNDLE_ID', 'org.probative.demo')

FileUtils.rm_rf(PROJECT_PATH)
project = Xcodeproj::Project.new(PROJECT_PATH)

target = project.new_target(:application, 'ProbativeDemo', :ios, '17.0')

# Sources de l'application.
group = project.new_group('Sources', 'Sources')
Dir.glob(File.join(DEMO, 'Sources', '*.swift')).sort.each do |path|
  ref = group.new_reference(path)
  target.add_file_references([ref])
end

# Le cœur est consommé comme paquet SwiftPM local — le XCFramework autonome
# est validé séparément par make_xcframework.sh. Référencer le paquet évite
# de reconstruire l'artefact à chaque itération sur le cœur.
package = project.new(Xcodeproj::Project::Object::XCLocalSwiftPackageReference)
package.relative_path = '..'
project.root_object.package_references << package

dependency = project.new(Xcodeproj::Project::Object::XCSwiftPackageProductDependency)
dependency.product_name = 'ProbativeCore'
target.package_product_dependencies << dependency

build_file = project.new(Xcodeproj::Project::Object::PBXBuildFile)
build_file.product_ref = dependency
target.frameworks_build_phase.files << build_file

target.build_configurations.each do |config|
  config.build_settings.merge!(
    'PRODUCT_BUNDLE_IDENTIFIER' => BUNDLE_ID,
    'PRODUCT_NAME' => '$(TARGET_NAME)',
    'DEVELOPMENT_TEAM' => TEAM,
    'CODE_SIGN_STYLE' => 'Automatic',
    'SWIFT_VERSION' => '5.0',
    'IPHONEOS_DEPLOYMENT_TARGET' => '17.0',
    'TARGETED_DEVICE_FAMILY' => '1,2',
    'MARKETING_VERSION' => '0.1',
    'CURRENT_PROJECT_VERSION' => '1',
    # Info.plist synthétisé : un fichier de moins à tenir à jour.
    'GENERATE_INFOPLIST_FILE' => 'YES',
    'INFOPLIST_KEY_UILaunchScreen_Generation' => 'YES',
    'INFOPLIST_KEY_CFBundleDisplayName' => 'probative',
    'INFOPLIST_KEY_UISupportedInterfaceOrientations' => 'UIInterfaceOrientationPortrait',
    # Le vecteur produit se récupère par devicectl ; l'exposer dans Fichiers
    # donne un second chemin de récupération quand le poste n'est pas là.
    'INFOPLIST_KEY_UIFileSharingEnabled' => 'YES',
    'INFOPLIST_KEY_LSSupportsOpeningDocumentsInPlace' => 'YES'
  )
end

project.save

# Schéma partagé : sans lui, xcodebuild ne sait pas résoudre la dépendance
# de paquet SwiftPM, et -target seul ne suffit pas.
scheme = Xcodeproj::XCScheme.new
scheme.add_build_target(target)
scheme.set_launch_target(target)
scheme.save_as(PROJECT_PATH, 'ProbativeDemo', true)

puts "projet : #{PROJECT_PATH}"
puts "bundle : #{BUNDLE_ID}   equipe : #{TEAM}"
